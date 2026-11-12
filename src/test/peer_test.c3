module tls::peer_test;

import tls;
import tls::peer_support;
import std::time, std::thread;

// A client context, the TCP connection and the TLS transport on top of it; closed in the right order.
struct Session
{
	Context ctx;
	TcpTransport tcp;
	TlsTransport* t;
}

// Connects to the local peer of `scenario` and verifies it as `name`.
fn void? Session.open(&self, String scenario, ClientConfig cfg, String name)
{
	self.ctx = tls::new_client_context(&cfg)!;
	self.tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!;
	self.t = tls::connect(&self.ctx, &self.tcp, name, 5 * time::SEC)!;
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

fn ClientConfig trusting_the_test_ca()
{
	return { .ca_file = peer_support::ca_file() };
}

fn void expect_version(String scenario, String name, String version)
{
	Session s;
	defer s.close();
	s.open(scenario, trusting_the_test_ca(), name)!!;
	assert(s.t.conn.version_name() == version);
	assert(s.t.conn.verify_result() == 0);
}

fn void test_peer_handshake_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	expect_version("tls13", "localhost", "TLSv1.3");
}

fn void test_peer_handshake_tls12() @test
{
	if (!peer_support::peers_ready()) return;
	expect_version("tls12", "localhost", "TLSv1.2");
}

fn void test_peer_rsa_certificate_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	expect_version("rsa13", "localhost", "TLSv1.3");
}

fn void test_peer_rsa_certificate_tls12() @test
{
	if (!peer_support::peers_ready()) return;
	expect_version("rsa12", "localhost", "TLSv1.2");
}

fn void test_peer_connect_by_ip_address() @test
{
	if (!peer_support::peers_ready()) return;
	// the certificate lists 127.0.0.1 as an IP address; the check uses the IP entry, not the name entry
	expect_version("tls13", "127.0.0.1", "TLSv1.3");
	expect_version("ip", "127.0.0.1", "TLSv1.3");
}

fn void test_peer_second_dns_name_in_the_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	// the TCP target is 127.0.0.1, the name that is verified (and sent as SNI) is another one
	expect_version("tls13", "test.example", "TLSv1.3");
}

fn void test_peer_certificate_with_only_an_address_does_not_match_a_name() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	assert(@catch(s.open("ip", trusting_the_test_ca(), "localhost")) == tls::HOSTNAME_MISMATCH);
}

fn void test_peer_wrong_name_is_refused_and_the_transport_stays_open() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	assert(@catch(s.open("tls13", trusting_the_test_ca(), "wrong.example")) == tls::HOSTNAME_MISMATCH);
	// a failed connect leaves the transport underneath with its owner
	assert(!s.tcp.closed);
	assert(s.t == null);
}

fn void test_peer_unknown_ca_is_refused_with_default_settings() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	ClientConfig cfg;
	assert(@catch(s.open("tls13", cfg, "localhost")) == tls::CERT_UNTRUSTED);
}

fn void test_peer_http_request_over_tls() @test
{
	if (!peer_support::peers_ready()) return;
	String[2] scenarios = { "tls13", "tls12" };
	foreach (scenario : scenarios)
	{
		Session s;
		defer s.close();
		s.open(scenario, trusting_the_test_ca(), "localhost")!!;
		s.t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
		char[] page = mem::new_array(char, 65536);
		defer free(page);
		usz total = 0;
		fault end;
		while (total < page.len)
		{
			usz? n = s.t.read(page[total..], 5 * time::SEC);
			if (catch err = n)
			{
				end = err;
				break;
			}
			total += n;
		}
		String text = (String)page[:total];
		assert(text.starts_with("HTTP/1.0 200 ok"), "response: %s", text);
		// the peer ends the stream with close_notify
		assert(end == tls::CLOSED, "ended with %s", end);
		// and the transport is then finished for writing
		assert(@catch(s.t.write("more", 1 * time::SEC)) == tls::CLOSED);
	}
}

fn void test_peer_echo_lines() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("rev13", trusting_the_test_ca(), "localhost")!!;
	char[64] buf;
	s.t.write("hello\n", 5 * time::SEC)!!;
	usz n = s.t.read(&buf, 5 * time::SEC)!!;
	assert(((String)buf[:n]).trim() == "olleh", "got %s", (String)buf[:n]);
	// a second round on the same connection, with a longer line
	s.t.write("transport layer security\n", 5 * time::SEC)!!;
	n = s.t.read(&buf, 5 * time::SEC)!!;
	assert(((String)buf[:n]).trim() == "ytiruces reyal tropsnart");
}

fn void test_peer_large_request_is_sent_in_pieces() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("tls13", trusting_the_test_ca(), "localhost")!!;
	// 200 KB of headers: more than one write piece and many records; the peer still answers
	char[] big = mem::new_array(char, 200000);
	defer free(big);
	big[..] = 'a';
	s.t.write("GET / HTTP/1.0\r\nX-Padding: ", 5 * time::SEC)!!;
	s.t.write(big, 5 * time::SEC)!!;
	s.t.write("\r\n\r\n", 5 * time::SEC)!!;
	char[16] head;
	usz n = s.t.read(&head, 5 * time::SEC)!!;
	assert(n > 0);
}

fn void test_peer_close_is_idempotent() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("tls13", trusting_the_test_ca(), "localhost")!!;
	s.t.close()!!;
	s.t.close()!!;
	char[8] buf;
	assert(@catch(s.t.read(&buf, 100 * time::MS)) == tls::CLOSED);
	assert(@catch(s.t.write("x", 100 * time::MS)) == tls::CLOSED);
	assert(s.tcp.closed);
}

fn void test_peer_transport_is_a_transport() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("tls13", trusting_the_test_ca(), "localhost")!!;
	// handed to code that only knows the interface
	Transport generic = s.t;
	generic.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
	char[16] buf;
	assert(generic.read(&buf, 5 * time::SEC)!! > 0);
	char[4] none;
	assert(generic.read(none[:0], 1 * time::SEC)!! == 0);
}

fn void test_peer_sees_the_server_name_on_the_wire() @test
{
	if (!peer_support::peers_ready()) return;
	// this peer prints every message it receives: the name has to be in the ClientHello itself, not only checked locally
	usz before = peer_support::log_count("trace13", "test.examp");
	Session s;
	{
		defer s.close();
		s.open("trace13", trusting_the_test_ca(), "test.example")!!;
		s.t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
		char[16] buf;
		s.t.read(&buf, 5 * time::SEC)!!;
	}
	usz after = before;
	for (int i = 0; i < 40 && after == before; i++)
	{
		thread::sleep_ms(50)!!;
		after = peer_support::log_count("trace13", "test.examp");
	}
	assert(after > before, "name seen %d times before, %d after", before, after);
}
