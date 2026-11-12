module tls::peer_data_test;

import tls;
import tls::engine_transport;
import tls::loopback;
import tls::peer_support;
import std::time, std::io;

faultdef WIRE_BROKE;

// A client context, the TCP connection and the TLS transport on top of it.
struct Session
{
	Context ctx;
	TcpTransport tcp;
	TlsTransport* t;
}

fn void? Session.open(&self, String scenario, String name = "localhost", Duration timeout = 5 * time::SEC)
{
	ClientConfig cfg = { .ca_file = peer_support::ca_file() };
	self.ctx = tls::new_client_context(&cfg)!;
	self.tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!;
	self.t = tls::connect(&self.ctx, &self.tcp, name, timeout)!;
}

fn void Session.close(&self)
{
	if (self.t)
	{
		(void)self.t.close();
		self.t.free();
	}
	else
	{
		(void)self.tcp.close();
	}
	self.ctx.free();
}

fn char[] pattern(usz size, char seed)
{
	char[] data = mem::new_array(char, (sz)size);
	foreach (i, &c : data) *c = (char)(i * 131 + i / 7 + seed);
	return data;
}

// Sends `data` and reads the same number of bytes back, using reads of `chunk` bytes.
fn char[] echo(TlsTransport* t, char[] data, usz chunk)
{
	t.write(data, 10 * time::SEC)!!;
	char[] back = mem::new_array(char, (sz)data.len);
	usz got = 0;
	while (got < data.len)
	{
		usz want = min(chunk, data.len - got);
		got += t.read(back[got:want], 10 * time::SEC)!!;
	}
	return back;
}

// ---- data through a real peer ----

fn void test_peer_data_echo_one_byte() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("sni")!!;
	char[] back = echo(s.t, "x", 16);
	defer free(back);
	assert((String)back == "x");
}

fn void check_boundaries(String scenario, String version)
{
	Session s;
	defer s.close();
	s.open(scenario)!!;
	assert(s.t.conn.version_name() == version);
	usz[5] sizes = { 1, 16383, 16384, 16385, 40000 };
	foreach (size : sizes)
	{
		char[] data = pattern(size, (char)size);
		defer free(data);
		char[] back = echo(s.t, data, 65536);
		defer free(back);
		assert(back == data);
	}
}

fn void test_peer_data_record_boundaries_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	check_boundaries("sni", "TLSv1.3");
}

fn void test_peer_data_record_boundaries_tls12() @test
{
	if (!peer_support::peers_ready()) return;
	check_boundaries("echo12", "TLSv1.2");
}

fn void check_mebibyte(String scenario)
{
	Session s;
	defer s.close();
	s.open(scenario)!!;
	// a mebibyte in 16 rounds, read back in chunks from 4 KiB to 64 KiB
	usz[4] chunks = { 4096, 16384, 65535, 8192 };
	usz total = 0;
	for (int round = 0; round < 16; round++)
	{
		char[] data = pattern(65536, (char)round);
		defer free(data);
		char[] back = echo(s.t, data, chunks[round % 4]);
		defer free(back);
		assert(back == data, "round %d differs", round);
		total += data.len;
	}
	assert(total == 1024 * 1024);
}

fn void test_peer_data_one_mebibyte_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	check_mebibyte("sni");
}

fn void test_peer_data_one_mebibyte_tls12() @test
{
	if (!peer_support::peers_ready()) return;
	check_mebibyte("echo12");
}

fn void test_peer_data_single_write_of_one_mebibyte() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("sni")!!;
	// one write call; the peer echoes while it reads, and the kernel buffers hold the rest
	char[] data = pattern(1024 * 1024, 5);
	defer free(data);
	char[] back = echo(s.t, data, 32768);
	defer free(back);
	assert(back == data);
}

// ---- how the other side ends the connection ----

fn void test_peer_close_notify_gives_closed() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("closer")!!;
	s.t.write("hi", 5 * time::SEC)!!;
	char[16] buf;
	usz n = s.t.read(&buf, 5 * time::SEC)!!;
	assert((String)buf[:n] == "bye");
	// the peer sent close_notify: a clean end, and again on every later read
	assert(@catch(s.t.read(&buf, 5 * time::SEC)) == tls::CLOSED);
	assert(@catch(s.t.read(&buf, 5 * time::SEC)) == tls::CLOSED);
	// nothing is sent to a peer that has closed
	assert(@catch(s.t.write("more", 5 * time::SEC)) == tls::CLOSED);
	s.t.close()!!;
}

fn void test_peer_drop_without_close_notify_is_truncation() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("dropper")!!;
	s.t.write("hi", 5 * time::SEC)!!;
	char[16] buf;
	fault f = @catch(s.t.read(&buf, 5 * time::SEC));
	assert(f == tls::TRUNCATED, "fault %s", f);
	// and it stays that way
	assert(@catch(s.t.read(&buf, 5 * time::SEC)) == tls::TRUNCATED);
}

fn void test_peer_use_after_close_and_double_close() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("sni")!!;
	s.t.close()!!;
	s.t.close()!!;
	char[8] buf;
	assert(@catch(s.t.read(&buf, 100 * time::MS)) == tls::CLOSED);
	assert(@catch(s.t.write("x", 100 * time::MS)) == tls::CLOSED);
	assert(s.tcp.closed);
}

// ---- timeouts and transport faults ----

fn void test_peer_silent_peer_times_out() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	// the peer accepts the connection and never answers: the failure is the timeout, not a TLS error
	assert(@catch(s.open("silent", "localhost", 500 * time::MS)) == tls::TIMEOUT);
	assert(s.t == null);
	assert(!s.tcp.closed);
}

fn void test_peer_garbage_is_a_protocol_error() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	fault f = @catch(s.open("garbage"));
	assert(f == tls::PROTOCOL_ERROR || f == tls::PROTOCOL_VERSION, "fault %s", f);
	assert(s.t == null);
	assert(!s.tcp.closed);
}

fn void test_peer_failed_connects_release_everything() @test
{
	if (!peer_support::peers_ready()) return;
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ClientConfig cfg = { .ca_file = peer_support::ca_file() };
	Context ctx = tls::new_client_context(&cfg)!!;
	defer ctx.free();
	String[2] scenarios = { "garbage", "silent" };
	foreach (scenario : scenarios)
	{
		TcpTransport tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!!;
		defer (void)tcp.close();
		assert(@catch(tls::connect(&ctx, &tcp, "localhost", 300 * time::MS, &ta)));
	}
	assert(ta.allocation_count() == 0);
}

fn void test_peer_transport_fault_in_the_handshake_passes_through() @test
{
	if (!loopback::pki_ready()) return;
	// the transport underneath breaks after a few reads, in the middle of the handshake: that fault, not a TLS one
	ServerEnd end;
	end.open(loopback::server_cfg("server"));
	defer end.release();
	end.read_limit = 100;
	end.reads_before_fault = 3;
	end.read_fault = WIRE_BROKE;
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	assert(@catch(tls::connect(&cctx, &end, "localhost")) == WIRE_BROKE);
}

fn void test_peer_transport_fault_after_the_handshake_passes_through() @test
{
	if (!loopback::pki_ready()) return;
	ServerEnd end;
	end.open(loopback::server_cfg("server"));
	defer end.release();
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	TlsTransport* t = tls::connect(&cctx, &end, "localhost")!!;
	defer t.free();
	end.reads_before_fault = 1;
	end.read_fault = WIRE_BROKE;
	char[8] buf;
	assert(@catch(t.read(&buf, time::SEC)) == WIRE_BROKE);
}

// ---- what the peer sees ----

fn usz line_count(String text)
{
	usz n = 0;
	foreach (line : text.tsplit("\n"))
	{
		if (line.len > 0) n++;
	}
	return n;
}

fn String sni_log()
{
	String path = peer_support::state_value("OUT").tconcat("/sni.log");
	if (!file::is_file(path)) return "";
	return (String)file::load_temp(path)!!;
}

fn void test_peer_sni_is_seen_by_the_peer() @test
{
	if (!peer_support::peers_ready()) return;
	usz before = line_count(sni_log());
	Session s;
	{
		defer s.close();
		s.open("sni", "localhost")!!;
	}
	String log = sni_log();
	assert(line_count(log) == before + 1, "log: %s", log);
	assert(log.trim().ends_with("localhost"));
	Session t;
	{
		defer t.close();
		t.open("sni", "test.example")!!;
	}
	String log2 = sni_log();
	assert(line_count(log2) == before + 2);
	assert(log2.trim().ends_with("test.example"));
	// an address is never sent as a name: the peer's callback is called with none
	Session u;
	{
		defer u.close();
		u.open("sni", "127.0.0.1")!!;
	}
	assert(!sni_log().contains("127.0.0.1"));
}
