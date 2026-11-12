// Test support: a client connection driven by hand over TCP, for tests that need the engine itself (sessions, key
// updates) rather than the transport adapter.
module tls::probe;

import tls;
import tls::peer_support;
import std::time, std::io;

struct Probe
{
	Context ctx;
	TcpTransport tcp;
	Conn conn;
	bool done;
	fault result;          // why the handshake failed, or the last failure of read
	fault import_result;   // result of offering the session, when one was given
}

// Connects to the peer of `scenario` and runs the handshake; `session` (from export_session) is offered first.
fn void Probe.start(&self, String scenario, ClientConfig cfg, String name, char[] session = {})
{
	self.ctx = tls::new_client_context(&cfg)!!;
	self.tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!!;
	self.conn = self.ctx.new_client_conn(name)!!;
	if (session.len > 0)
	{
		if (catch f = self.conn.import_session(session)) self.import_result = f;
	}
	self.run_handshake();
}

// Closes the connection the polite way and frees everything.
fn void Probe.release(&self)
{
	if (self.done)
	{
		(void)self.conn.close_notify();
		self.send_pending();
	}
	(void)self.tcp.close();
	self.conn.free();
	self.ctx.free();
}

fn void Probe.send_pending(&self)
{
	char[4096] chunk;
	while (self.conn.out_pending() > 0)
	{
		usz n = self.conn.take_out(&chunk);
		if (n == 0) break;
		if (@catch(self.tcp.write(chunk[:n], 2 * time::SEC))) break;
	}
}

// One read from the network into the engine. False when nothing more came.
fn bool Probe.pull(&self, Duration timeout)
{
	char[18437] buf;
	usz? n = self.tcp.read(&buf, timeout);
	if (catch err = n)
	{
		if (err == tls::CLOSED) self.conn.feed_eof();
		return err == tls::CLOSED;
	}
	return self.conn.feed(buf[:n]) == n;
}

fn void Probe.run_handshake(&self)
{
	for (int i = 0; i < 2000; i++)
	{
		bool? d = self.conn.handshake();
		self.send_pending();
		if (catch f = d)
		{
			self.result = f;
			return;
		}
		if (d)
		{
			self.done = true;
			return;
		}
		if (!self.pull(5 * time::SEC))
		{
			self.result = tls::TIMEOUT;
			return;
		}
	}
}

fn void? Probe.send(&self, String text)
{
	self.conn.write((char[])text)!;
	self.send_pending();
}

// Plaintext from the peer, waiting up to `wait` for the first bytes. Empty when nothing came (a failure is in `result`).
// Key updates and other replies the engine wants to send go out while it reads.
fn String Probe.receive(&self, char[] buf, Duration wait)
{
	for (int i = 0; i < 2000; i++)
	{
		usz? n = self.conn.read(buf);
		self.send_pending();
		if (catch f = n)
		{
			if (f == tls::WANT_INPUT)
			{
				if (!self.pull(wait)) return "";
				continue;
			}
			self.result = f;
			return "";
		}
		return (String)buf[:n];
	}
	return "";
}

// An HTTP request to a -www peer, and the start of the answer: this is what lets a TLS 1.3 client see the server's tickets.
fn String Probe.request_page(&self)
{
	self.send("GET / HTTP/1.0\r\n\r\n")!!;
	char[256] buf;
	return self.receive(&buf, 5 * time::SEC);
}

// After the handshake: read until the peer has said what it wants (data, an alert, the end), or stays quiet.
fn void Probe.read_for_a_while(&self)
{
	char[1024] buf;
	for (int i = 0; i < 2000; i++)
	{
		usz? n = self.conn.read(&buf);
		self.send_pending();
		if (catch f = n)
		{
			if (f == tls::WANT_INPUT)
			{
				if (!self.pull(1 * time::SEC)) return;
				continue;
			}
			self.result = f;
			return;
		}
	}
}
