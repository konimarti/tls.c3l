// Backend independent: uses only the Context/Conn API of engine.c3 and the Transport interface.
module tls;
import tls::wire;
import std::time;

// How much plaintext goes into the engine per call; the encrypted records are sent after each piece.
const usz WRITE_PIECE = 65536;
const Duration CLOSE_FLUSH_TIMEOUT = 2 * time::SEC;

// A Transport that encrypts. It owns the transport underneath once connect or accept succeeded.
struct TlsTransport (Transport)
{
	Context* ctx;              // not owned
	Conn conn;
	Transport inner;
	char[] inbuf;              // largest possible record
	char[] outbuf;
	bool closed;
	bool peer_closed;          // close_notify received
	fault broken;              // the transport underneath failed to take bytes the engine had produced
	Allocator allocator;
}

// Client side: the handshake runs on `inner` and must finish within `timeout` in total (zero = no limit): every wait
// gets only what is left of it, so a peer that trickles data cannot keep the call open.
// On failure nothing is closed: `inner` still belongs to the caller. On success it belongs to the result.
fn TlsTransport*? connect(Context* ctx, Transport inner, String server_name, Duration timeout = time::DURATION_ZERO, Allocator allocator = mem)
{
	TlsTransport* t = new_transport(ctx, inner, allocator)!;
	// everything the transport owns exists before the connection is made, so any failure below frees it all in one place
	Conn? conn = ctx.new_client_conn(server_name, allocator);
	if (catch err = conn)
	{
		t.free();
		return err~;
	}
	return finish_handshake(t, conn, timeout);
}

// Server side: the same, for a connection that was accepted. A client certificate demanded by the context that does
// not come is NO_PEER_CERT.
fn TlsTransport*? accept(Context* ctx, Transport inner, Duration timeout = time::DURATION_ZERO, Allocator allocator = mem)
{
	TlsTransport* t = new_transport(ctx, inner, allocator)!;
	Conn? conn = ctx.new_server_conn(allocator);
	if (catch err = conn)
	{
		t.free();
		return err~;
	}
	return finish_handshake(t, conn, timeout);
}

fn TlsTransport*? finish_handshake(TlsTransport* t, Conn conn, Duration timeout)
{
	t.conn = conn;
	if (catch err = t.run_handshake(timeout))
	{
		t.free();
		return err~;
	}
	return t;
}

fn TlsTransport*? new_transport(Context* ctx, Transport inner, Allocator allocator)
{
	TlsTransport* t = alloc::new_try(allocator, TlsTransport)!;
	t.ctx = ctx;
	t.inner = inner;
	t.allocator = allocator;
	// free() copes with buffers that were never allocated
	t.inbuf = alloc::alloc_array_try(allocator, char, (sz)wire::RECORD_MAX_WIRE) ?? {};
	t.outbuf = alloc::alloc_array_try(allocator, char, (sz)wire::RECORD_MAX_WIRE) ?? {};
	if (t.inbuf.len == 0 || t.outbuf.len == 0)
	{
		t.free();
		return OUT_OF_MEMORY~;
	}
	return t;
}

// Sends everything the engine has queued.
fn void? TlsTransport.flush(&self, Duration timeout)
{
	if (self.broken) return self.broken~;
	while (self.conn.out_pending() > 0)
	{
		usz n = self.conn.take_out(self.outbuf);
		if (n == 0) break;
		if (catch err = self.inner.write(self.outbuf[:n], timeout))
		{
			// the bytes have left the engine and the transport may have sent part of them: whether a retry would repeat
			// or skip data is unknown, and the peer would end the session on the gap. The stream is lost.
			self.broken = err;
			return err~;
		}
	}
}

// Reads from the network into the engine. End of the network stream tells the engine, which then decides between a
// clean end and truncation.
fn void? TlsTransport.pull(&self, Duration timeout)
{
	usz? n = self.inner.read(self.inbuf, timeout);
	if (catch err = n)
	{
		if (err == CLOSED)
		{
			self.conn.feed_eof();
			return;
		}
		return err~;
	}
	// everything fits: this is only called when the engine wants input, with at most one record buffered
	if (self.conn.feed(self.inbuf[:n]) != n) return OPENSSL_ERROR~;
}

// What is left of a total allowance `total` that started at `started`. A total of zero or less means no limit.
fn Duration? time_left(Clock started, Duration total)
{
	if (total <= time::DURATION_ZERO) return total;
	Duration elapsed = started.to_now().to_duration();
	if (elapsed >= total) return TIMEOUT~;
	return total - elapsed;
}

fn void? TlsTransport.run_handshake(&self, Duration timeout)
{
	Clock started = clock::now();
	while (true)
	{
		bool? done = self.conn.handshake();
		if (catch err = done)
		{
			// a fatal alert may be waiting: the peer should hear it, but its failure to take it changes nothing
			Duration? left = time_left(started, timeout);
			if (try d = left) (void)self.flush(d);
			return err~;
		}
		self.flush(time_left(started, timeout)!)!;
		if (done) return;
		self.pull(time_left(started, timeout)!)!;
	}
}

fn usz? TlsTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (self.broken) return self.broken~;
	if (buf.len == 0) return 0;
	Clock started = clock::now();
	while (true)
	{
		usz? n = self.conn.read(buf);
		if (catch err = n)
		{
			// the engine may have queued something even while it had nothing to hand back: key updates, alerts
			Duration? left = time_left(started, timeout);
			if (try d = left) (void)self.flush(d);
			if (err == WANT_INPUT)
			{
				// the whole call gets `timeout`, however slowly the peer delivers; a partial record stays in the
				// engine, so a later read carries on where this one stopped
				self.pull(time_left(started, timeout)!)!;
				continue;
			}
			if (err == CLOSED) self.peer_closed = true;
			return err~;
		}
		// plaintext that was already decrypted is never thrown away because the network refused our reply; the failure
		// is remembered and the next call reports it
		Duration? left = time_left(started, timeout);
		if (try d = left) (void)self.flush(d);
		return n;
	}
}

// All of data or a fault. After the peer's close_notify this is CLOSED: TLS would allow sending on, but a peer that has
// closed its side is not expected to read. After a fault the TlsTransport is unusable: the data of the failed call may or may not be on
// its way, and every later read or write returns the same fault (reconnect instead of retrying).
fn void? TlsTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed || self.peer_closed) return CLOSED~;
	if (self.broken) return self.broken~;
	Clock started = clock::now();
	usz done = 0;
	while (done < data.len)
	{
		usz piece = min((usz)data.len - done, WRITE_PIECE);
		usz? w = self.conn.write(data[done:piece]);
		if (catch err = w)
		{
			// the engine wants input first (the peer started something that needs an answer): get it and try again
			if (err == WANT_INPUT)
			{
				self.pull(time_left(started, timeout)!)!;
				continue;
			}
			return err~;
		}
		self.flush(time_left(started, timeout)!)!;
		done += piece;
	}
}

// Sends close_notify (without waiting for the peer's), then closes the transport underneath.
fn void? TlsTransport.close(&self) @dynamic
{
	if (self.closed) return;
	self.closed = true;
	self.conn.close_notify()!;
	(void)self.flush(CLOSE_FLUSH_TIMEOUT); // best effort: a peer that stopped reading must not hang the close
	return self.inner.close();
}

// Frees the connection and its buffers, not the Context and not the transport underneath.
fn void TlsTransport.free(&self)
{
	self.conn.free();
	if (self.inbuf.ptr) alloc::free(self.allocator, self.inbuf.ptr);
	if (self.outbuf.ptr) alloc::free(self.allocator, self.outbuf.ptr);
	alloc::free(self.allocator, self);
}
