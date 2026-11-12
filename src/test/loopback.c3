// Test support: two engines connected in memory, no sockets and no peer process.
module tls::loopback;

import tls;
import tls::ossl;
import std::io, std::os::env;

// What a test that needs the generated certificates does when they may be missing.
enum PkiDecision { RUN, SKIP, FAIL }

fn PkiDecision pki_decision(bool present, bool required)
{
	if (present) return RUN;
	return required ? FAIL : SKIP;
}

// The certificates come from tests/pki/make-pki.sh. Without them a test prints a note and passes, unless the
// environment variable TLS_REQUIRE_PKI is set (CI sets it): then a missing PKI fails the test instead of hiding it.
fn bool pki_ready()
{
	bool required = @ok(env::tget_var("TLS_REQUIRE_PKI"));
	PkiDecision d = pki_decision(file::is_file("tests/pki/out/.complete"), required);
	assert(d != FAIL, "tests/pki/out is missing and TLS_REQUIRE_PKI is set: run tests/pki/make-pki.sh");
	if (d == SKIP) io::printn("SKIP: tests/pki/out is missing, run tests/pki/make-pki.sh");
	return d == RUN;
}

fn String pki(String name) => "tests/pki/out/".tconcat(name);

// Bytes taken out of one engine that the other could not accept yet (its input buffer was full).
struct Wire
{
	char[8192] left;
	usz left_len;
}

struct Link
{
	Wire to_server;
	Wire to_client;
	bool slow;      // deliver one byte per round
}

// Moves queued ciphertext from `from` into `to`; returns the number of bytes delivered.
fn usz move(Conn* from, Conn* to, Wire* w, bool slow)
{
	usz moved = 0;
	char[4096] chunk;
	while (true)
	{
		if (w.left_len == 0)
		{
			usz want = slow ? 1 : chunk.len;
			usz n = from.take_out(chunk[:want]);
			if (n == 0) break;
			w.left[:n][..] = chunk[:n][..];
			w.left_len = n;
		}
		usz fed = to.feed(w.left[:w.left_len]);
		if (fed == 0) break;
		moved += fed;
		for (usz i = 0; i + fed < w.left_len; i++) w.left[i] = w.left[i + fed];
		w.left_len -= fed;
		if (slow || w.left_len > 0) break;
	}
	return moved;
}

fn bool wire_empty(Conn* from, Wire* w) => w.left_len == 0 && from.out_pending() == 0;

struct Outcome
{
	bool client_done;
	bool server_done;
	fault client_fault;
	fault server_fault;
}

// Drives both handshakes and moves the bytes between them until both finished, failed, or nothing moves any more.
fn Outcome run_handshake(Conn* c, Conn* s, Link* link)
{
	Outcome o;
	for (int round = 0; round < 400000; round++)
	{
		bool changed = false;
		if (!o.client_done && !o.client_fault)
		{
			bool? r = c.handshake();
			if (catch f = r)
			{
				o.client_fault = f;
				changed = true;
			}
			else if (r)
			{
				o.client_done = true;
				changed = true;
			}
		}
		if (!o.server_done && !o.server_fault)
		{
			bool? r = s.handshake();
			if (catch f = r)
			{
				o.server_fault = f;
				changed = true;
			}
			else if (r)
			{
				o.server_done = true;
				changed = true;
			}
		}
		usz moved = move(c, s, &link.to_server, link.slow) + move(s, c, &link.to_client, link.slow);
		bool finished = (o.client_done || o.client_fault) && (o.server_done || o.server_fault);
		if (finished && wire_empty(c, &link.to_server) && wire_empty(s, &link.to_client)) break;
		if (moved == 0 && !changed) break;
	}
	return o;
}

// Two contexts and two connections, connected through a Link. Must not move after open().
struct Pair
{
	Context cctx;
	Context sctx;
	Conn c;
	Conn s;
	Link link;
	Outcome outcome;
}

fn ServerConfig server_cfg(String name)
{
	return { .cert_file = pki(name.tconcat(".pem")), .key_file = pki(name.tconcat(".key")) };
}

fn ClientConfig client_cfg()
{
	return { .ca_file = pki("ca.pem") };
}

// Builds the engines and runs the handshake. `name` is what the client verifies.
fn void Pair.open(&self, ClientConfig ccfg, ServerConfig scfg, String name, bool slow = false)
{
	self.cctx = tls::new_client_context(&ccfg)!!;
	self.sctx = tls::new_server_context(&scfg)!!;
	self.c = self.cctx.new_client_conn(name)!!;
	self.s = self.sctx.new_server_conn()!!;
	self.link.slow = slow;
	self.outcome = run_handshake(&self.c, &self.s, &self.link);
}

fn void Pair.close(&self)
{
	self.c.free();
	self.s.free();
	self.cctx.free();
	self.sctx.free();
}

// Writes `data` through `from`, delivers it to `to` and reads it there; returns what `to` received.
fn char[] transfer(Pair* p, bool from_client, char[] data)
{
	Conn* from = from_client ? &p.c : &p.s;
	Conn* to = from_client ? &p.s : &p.c;
	Wire* forward = from_client ? &p.link.to_server : &p.link.to_client;
	Wire* back = from_client ? &p.link.to_client : &p.link.to_server;
	char[] got = mem::new_array(char, (sz)data.len);
	char[8192] buf;
	usz sent = 0;
	usz received = 0;
	for (int round = 0; round < 2000000 && received < data.len; round++)
	{
		if (sent < data.len)
		{
			usz n = min(data.len - sent, (usz)16384);
			assert(from.write(data[sent:n])!! == n);
			sent += n;
		}
		usz moved = move(from, to, forward, p.link.slow);
		while (true)
		{
			usz? n = to.read(&buf);
			if (catch e = n)
			{
				assert(e == tls::WANT_INPUT);
				break;
			}
			got[received:n][..] = buf[:n][..];
			received += n;
		}
		moved += move(to, from, back, p.link.slow);
		if (moved == 0 && sent == data.len && from.out_pending() == 0) break;
	}
	assert(received == data.len);
	return got;
}

// A server connection with nothing attached: for feeding it hand-made bytes.
struct Lone
{
	Context ctx;
	Conn conn;
}

fn void Lone.open(&self, String cert = "server")
{
	ServerConfig cfg = server_cfg(cert);
	self.ctx = tls::new_server_context(&cfg)!!;
	self.conn = self.ctx.new_server_conn()!!;
}

fn void Lone.close(&self)
{
	self.conn.free();
	self.ctx.free();
}

// Everything the connection has queued for the network.
fn char[] drain(Conn* c)
{
	char[] out = mem::new_array(char, (sz)c.out_pending());
	usz at = 0;
	while (at < out.len)
	{
		usz n = c.take_out(out[at..]);
		if (n == 0) break;
		at += n;
	}
	return out[:at];
}

// The first alert record in `bytes` as {level, description}, or {0, 0}.
fn char[2] first_alert(char[] bytes)
{
	usz at = 0;
	while (at + 5 <= bytes.len)
	{
		usz len = (usz)bytes[at + 3] << 8 | bytes[at + 4];
		if (bytes[at] == 21 && at + 7 <= bytes.len) return { bytes[at + 5], bytes[at + 6] };
		at += 5 + len;
	}
	return { 0, 0 };
}

fn bool contains_text(String haystack, String needle)
{
	return haystack.to_lower_tcopy().contains(needle);
}
