// Plain TCP transport. The only file that knows about poll / WSAPoll (through std::net::poll).
module tls;
import std::net, std::net::tcp, std::net::os, std::time, std::io;
import libc;

// Largest piece handed to one send(): after poll() reports the socket writable, a send of this size cannot
// block for long, so the timeout stays meaningful for large writes.
const usz TCP_WRITE_CHUNK = 16384;
const CInt EPIPE = 32; // the same value on Linux and macOS
const CInt DARWIN_SOL_SOCKET = 0xffff;
const CInt DARWIN_SO_NOSIGPIPE = 0x1022;

struct TcpTransport (Transport)
{
	TcpSocket sock;
	bool closed;
}

fn TcpTransport? tcp_connect(String host, int port, Duration timeout = time::DURATION_ZERO)
{
	TcpTransport t = { .sock = tcp::connect(host, port, timeout)! };
	no_sigpipe(t.sock.sock);
	return t;
}

// macOS has no MSG_NOSIGNAL: a write to a closed peer would kill the process with SIGPIPE unless the socket says no.
fn void no_sigpipe(NativeSocket sock)
{
$if env::DARWIN:
	CInt on = 1;
	os::setsockopt(sock, DARWIN_SOL_SOCKET, DARWIN_SO_NOSIGPIPE, &on, CInt::size);
$endif
}

// Wraps a socket obtained elsewhere (for example from tcp::accept).
fn TcpTransport tcp_wrap(TcpSocket sock)
{
	no_sigpipe(sock.sock);
	return { .sock = sock };
}

// Waits until the socket is ready for `events`. DURATION_ZERO (or less) waits forever.
fn void? tcp_wait(NativeSocket sock, PollSubscribe events, Duration timeout)
{
	Duration t = timeout > time::DURATION_ZERO ? timeout : net::POLL_FOREVER;
	Poll[1] polls = { { .socket = sock, .events = events } };
	while (true)
	{
		ulong? ready = net::poll(polls[..], t);
		if (catch err = ready)
		{
			if (err == io::INTERRUPTED) continue;
			return err~;
		}
		if (ready == 0) return TIMEOUT~;
		return;
	}
}

fn bool is_peer_gone(fault err) => err == net::CONNECTION_RESET;

fn usz? TcpTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (buf.len == 0) return 0;
	while (true)
	{
		tcp_wait(self.sock.sock, ANY_READ, timeout)!;
		sz? n = self.sock.read(buf);
		if (catch err = n)
		{
			if (err == io::INTERRUPTED) continue; // a signal, not a result: wait again
			if (is_peer_gone(err)) return CLOSED~;
			return err~;
		}
		if (n == 0) return CLOSED~;
		return (usz)n;
	}
}

// One send() that never raises SIGPIPE where the platform lets us ask for that.
fn sz? tcp_send(TcpSocket* sock, char[] chunk)
{
$if env::LINUX || env::DARWIN:
$if env::LINUX:
	CInt flags = os::MSG_NOSIGNAL;
$else
	CInt flags = 0; // SO_NOSIGPIPE is set on the socket
$endif
	sz n = libc::send(sock.sock, chunk.ptr, chunk.len, flags);
	if (n < 0)
	{
		Errno e = libc::errno();
		if ((CInt)e == EPIPE) return CLOSED~;
		return os::convert_error(e)~;
	}
	return n;
$else
	return sock.write(chunk);
$endif
}

fn void? TcpTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	usz done = 0;
	while (done < data.len)
	{
		usz len = min(data.len - done, TCP_WRITE_CHUNK);
		tcp_wait(self.sock.sock, ANY_WRITE, timeout)!;
		sz? n = tcp_send(&self.sock, data[done:len]);
		if (catch err = n)
		{
			if (err == io::INTERRUPTED) continue;
			if (is_peer_gone(err)) return CLOSED~;
			return err~;
		}
		done += (usz)n;
	}
}

fn void? TcpTransport.close(&self) @dynamic
{
	if (self.closed) return;
	self.closed = true;
	return self.sock.close();
}
