// Test support: a TLS server engine behind the Transport interface, so a TlsTransport can be tested without sockets.
// Everything is synchronous: a write is processed at once and whatever the server answers waits for the next read.
module tls::engine_transport;

import tls;
import std::collections::list, std::time, std::thread;

struct ServerEnd (Transport)
{
	Context ctx;
	Conn server;
	List{char} inbox;          // ciphertext from the server, waiting to be read by the client
	usz read_pos;
	List{char} received;       // plaintext the server has decrypted
	int fail_writes;           // the next writes fail with TIMEOUT without reaching the server
	usz read_limit;            // 0 = no limit, otherwise at most this many bytes per read
	int read_delay_ms;         // every read takes this long
	int reads_before_fault;    // after this many reads, every read fails with `read_fault` (0 = never)
	fault read_fault;
	bool read_fault_active;
	bool closed;
}

fn void ServerEnd.open(&self, ServerConfig cfg)
{
	self.ctx = tls::new_server_context(&cfg)!!;
	self.server = self.ctx.new_server_conn()!!;
	self.inbox.init(mem);
	self.received.init(mem);
}

fn void ServerEnd.release(&self)
{
	self.server.free();
	self.ctx.free();
	self.inbox.free();
	self.received.free();
}

// Moves what the server has queued into the inbox.
fn void ServerEnd.collect(&self)
{
	char[4096] chunk;
	while (self.server.out_pending() > 0)
	{
		usz n = self.server.take_out(&chunk);
		if (n == 0) break;
		self.inbox.push_all(chunk[:n]);
	}
}

fn usz? ServerEnd.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.closed) return tls::CLOSED~;
	if (buf.len == 0) return 0;
	if (self.read_delay_ms > 0) thread::sleep_ms(self.read_delay_ms)!!;
	if (self.reads_before_fault > 0 && --self.reads_before_fault == 0) self.read_fault_active = true;
	if (self.read_fault_active) return self.read_fault~;
	usz avail = (usz)self.inbox.len() - self.read_pos;
	if (avail == 0)
	{
		self.inbox.clear();
		self.read_pos = 0;
		return tls::TIMEOUT~;
	}
	usz n = min(avail, (usz)buf.len);
	if (self.read_limit > 0) n = min(n, self.read_limit);
	buf[:n][..] = self.inbox.array_view()[self.read_pos:n][..];
	self.read_pos += n;
	return n;
}

fn void? ServerEnd.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed) return tls::CLOSED~;
	if (self.fail_writes > 0)
	{
		self.fail_writes--;
		return tls::TIMEOUT~;
	}
	usz at = 0;
	while (at < data.len)
	{
		usz fed = self.server.feed(data[at..]);
		at += fed;
		self.step();
		if (fed == 0) break;
	}
}

// Lets the server make progress on what it has been given.
fn void ServerEnd.step(&self)
{
	if (!self.server.handshake_done)
	{
		(void)self.server.handshake();
	}
	else
	{
		char[4096] buf;
		while (true)
		{
			usz? n = self.server.read(&buf);
			if (catch err = n) break;
			self.received.push_all(buf[:n]);
		}
	}
	self.collect();
}

fn void? ServerEnd.close(&self) @dynamic
{
	self.closed = true;
}

fn String ServerEnd.text(&self) => (String)self.received.array_view();
