module tls::peer_features_test;

import tls;
import tls::peer_support;
import std::time, std::io, std::thread, std::encoding::hex, std::hash::sha256;

// The peers are openssl s_server processes: one connection at a time, so close() a session before opening another to
// the same peer.
struct Session
{
	Context ctx;
	TcpTransport tcp;
	TlsTransport* t;
	bool released;
}

fn void? Session.open(&self, String scenario, ClientConfig cfg, String name)
{
	self.ctx = tls::new_client_context(&cfg)!;
	self.tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!;
	self.t = tls::connect(&self.ctx, &self.tcp, name, 5 * time::SEC)!;
}

fn void Session.close(&self)
{
	if (self.released) return;
	self.released = true;
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

fn ClientConfig with_ca()
{
	return { .ca_file = peer_support::ca_file() };
}

fn String hex_of(char[] bytes) => hex::tencode(bytes);

// ---- ALPN ----

fn void test_peer_alpn_server_picks_the_first_match() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = with_ca();
	cfg.alpn = { "http/1.1", "h2" };
	Session s;
	defer s.close();
	s.open("alpn", cfg, "localhost")!!;
	// the server prefers its own order: h2 first
	assert(s.t.conn.alpn_selected() == "h2", "selected %s", s.t.conn.alpn_selected());
}

fn void test_peer_alpn_without_a_common_protocol_is_refused_by_this_server() @test
{
	if (!peer_support::peers_ready()) return;
	// openssl s_server answers an offer it cannot match with the no_application_protocol alert
	ClientConfig cfg = with_ca();
	cfg.alpn = { "foo" };
	Session s;
	defer s.close();
	assert(@catch(s.open("alpn", cfg, "localhost")) == tls::ALERT_RECEIVED);
}

fn void test_peer_alpn_not_selected_by_the_server_is_optional_by_default() @test
{
	if (!peer_support::peers_ready()) return;
	// a server that does not do ALPN at all: the connection works, nothing is selected
	ClientConfig cfg = with_ca();
	cfg.alpn = { "h2" };
	Session s;
	defer s.close();
	s.open("tls13", cfg, "localhost")!!;
	assert(s.t.conn.alpn_selected() == "");
}

fn void test_peer_alpn_required_but_not_selected_is_a_fault() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = with_ca();
	cfg.alpn = { "h2" };
	cfg.require_alpn = true;
	Session s;
	defer s.close();
	assert(@catch(s.open("tls13", cfg, "localhost")) == tls::ALPN_MISMATCH);
	assert(s.t == null);
	s.close();
	// required and available
	Session t;
	defer t.close();
	t.open("alpn", cfg, "localhost")!!;
	assert(t.t.conn.alpn_selected() == "h2");
}

fn void offer_and_wait(String scenario, String[] names)
{
	ClientConfig cfg = with_ca();
	cfg.alpn = names;
	Session s;
	defer s.close();
	// the server knows none of these: it refuses, but it has seen the offer
	assert(@catch(s.open(scenario, cfg, "localhost")) == tls::ALERT_RECEIVED);
}

fn void test_peer_alpn_lists_reach_the_peer() @test
{
	if (!peer_support::peers_ready()) return;
	// "mqtt" is a substring of "x-amzn-mqtt-ca": the trace prints one name per line, so whole lines are counted
	usz mqtt = peer_support::log_count_line("alpn", "mqtt");
	usz amzn = peer_support::log_count_line("alpn", "x-amzn-mqtt-ca");
	String[1] only_amzn = { "x-amzn-mqtt-ca" };
	offer_and_wait("alpn", only_amzn[..]);
	usz after_amzn = amzn;
	for (int i = 0; i < 40 && after_amzn == amzn; i++)
	{
		thread::sleep_ms(50)!!;
		after_amzn = peer_support::log_count_line("alpn", "x-amzn-mqtt-ca");
	}
	assert(after_amzn == amzn + 1, "x-amzn-mqtt-ca lines %d -> %d", amzn, after_amzn);
	// the log is ordered: the whole offer has been printed, and it held no "mqtt"
	assert(peer_support::log_count_line("alpn", "mqtt") == mqtt);
	// both names offered: both lines appear
	String[2] both = { "mqtt", "x-amzn-mqtt-ca" };
	offer_and_wait("alpn", both[..]);
	usz after_mqtt = mqtt;
	for (int i = 0; i < 40 && after_mqtt == mqtt; i++)
	{
		thread::sleep_ms(50)!!;
		after_mqtt = peer_support::log_count_line("alpn", "mqtt");
	}
	assert(after_mqtt == mqtt + 1, "mqtt lines %d -> %d", mqtt, after_mqtt);
	assert(peer_support::log_count_line("alpn", "x-amzn-mqtt-ca") == after_amzn + 1);
}

fn void test_peer_alpn_not_offered_gives_an_empty_slice() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("alpn", with_ca(), "localhost")!!;
	assert(s.t.conn.alpn_selected().len == 0);
}

// ---- server name selects the certificate ----

fn void test_peer_sni_selects_another_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	// alt.test is only in the second certificate; it verifies only if the name was sent
	Session a;
	defer a.close();
	a.open("sni2", with_ca(), "alt.test")!!;
	char[] alt = a.t.conn.peer_cert_sha256()!!;
	defer free(alt);
	a.close();
	Session b;
	defer b.close();
	b.open("sni2", with_ca(), "localhost")!!;
	char[] main = b.t.conn.peer_cert_sha256()!!;
	defer free(main);
	b.close();
	assert(alt != main);
	// and the default certificate does not carry that name
	Session c;
	defer c.close();
	assert(@catch(c.open("tls13", with_ca(), "alt.test")) == tls::HOSTNAME_MISMATCH);
}

// ---- trust sources ----

fn void test_peer_trust_ca_directory() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = { .ca_dir = peer_support::pki_file("hashed") };
	Session s;
	defer s.close();
	s.open("tls13", cfg, "localhost")!!;
}

fn void test_peer_trust_custom_ca_replaces_system_roots() @test
{
	if (!peer_support::peers_ready()) return;
	// a server signed by another CA fails with only the test CA configured
	Session s;
	defer s.close();
	assert(@catch(s.open("untrusted", with_ca(), "localhost")) == tls::CERT_UNTRUSTED);
	s.close();
	// with no CA configured the system store is used, and does not know the test CA
	ClientConfig none;
	Session t;
	defer t.close();
	assert(@catch(t.open("tls13", none, "localhost")) == tls::CERT_UNTRUSTED);
	t.close();
	// the system store can be added to a custom CA
	ClientConfig both = with_ca();
	both.also_system_roots = true;
	Session u;
	defer u.close();
	u.open("tls13", both, "localhost")!!;
}

// ---- client certificates ----

fn ClientConfig with_client_certificate(String cert, String key)
{
	ClientConfig cfg = with_ca();
	cfg.client_cert_file = peer_support::pki_file(cert);
	cfg.client_key_file = peer_support::pki_file(key);
	return cfg;
}

fn void test_peer_mtls_with_a_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	String[2] peers = { "mtls-wrongca", "mtls12" };
	foreach (scenario : peers)
	{
		Session s;
		defer s.close();
		s.open(scenario, with_client_certificate("client.pem", "client.key"), "localhost")!!;
		s.t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
		char[16] buf;
		assert(s.t.read(&buf, 5 * time::SEC)!! > 0);
	}
}

fn void test_peer_mtls_certificate_that_does_not_match_its_key() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = with_client_certificate("client.pem", "key-mismatch.key");
	assert(@catch(tls::new_client_context(&cfg)) == tls::KEY_LOAD_FAILED);
}

// ---- pinning and the peer certificate ----

fn char[] fingerprint(String key)
{
	String text = peer_support::state_value(key);
	return hex::tdecode(text)!!;
}

fn void test_peer_pin_self_signed_certificate_without_any_ca() @test
{
	if (!peer_support::peers_ready()) return;
	char[] pin = fingerprint("SHA256_selfsigned");
	ClientConfig cfg = { .verify = PINNED_ONLY, .pin_sha256 = pin };
	Session s;
	defer s.close();
	s.open("selfsigned", cfg, "localhost")!!;
	// the fingerprint the engine reports is the one computed outside
	char[] seen = s.t.conn.peer_cert_sha256()!!;
	defer free(seen);
	assert(seen == pin);
	s.close();
	// a different pin is refused
	char[32] wrong;
	wrong[..] = pin[..];
	wrong[0] ^= 0x80;
	ClientConfig bad = { .verify = PINNED_ONLY, .pin_sha256 = wrong[..] };
	Session t;
	defer t.close();
	assert(@catch(t.open("selfsigned", bad, "localhost")) == tls::PIN_MISMATCH);
}

fn void test_peer_pin_applies_on_top_of_full_verification() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = with_ca();
	cfg.pin_sha256 = fingerprint("SHA256_server");
	Session s;
	defer s.close();
	s.open("tls13", cfg, "localhost")!!;
	s.close();
	char[32] wrong;
	wrong[..] = 0x11;
	cfg.pin_sha256 = wrong[..];
	Session t;
	defer t.close();
	assert(@catch(t.open("tls13", cfg, "localhost")) == tls::PIN_MISMATCH);
}

fn void test_peer_certificate_in_der_form() @test
{
	if (!peer_support::peers_ready()) return;
	Session s;
	defer s.close();
	s.open("tls13", with_ca(), "localhost")!!;
	char[] der = s.t.conn.peer_cert_der()!!;
	defer free(der);
	// a DER certificate is a SEQUENCE, and its SHA-256 is the fingerprint computed outside
	assert(der[0] == 0x30);
	assert(hex_of(sha256::hash(der)[..]) == peer_support::state_value("SHA256_server"));
	char[] sha = s.t.conn.peer_cert_sha256()!!;
	defer free(sha);
	assert(hex_of(sha) == peer_support::state_value("SHA256_server"));
}

// ---- key exchange groups ----

fn void test_peer_groups_restricted_to_one_curve() @test
{
	if (!peer_support::peers_ready()) return;
	usz hybrid = peer_support::log_count("trace13", "NamedGroup: X25519MLKEM768");
	ClientConfig narrow = with_ca();
	narrow.groups = "P-256";
	{
		Session s;
		defer s.close();
		s.open("trace13", narrow, "localhost")!!;
		s.t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
		char[16] buf;
		s.t.read(&buf, 5 * time::SEC)!!;
	}
	thread::sleep_ms(300)!!;
	assert(peer_support::log_count("trace13", "NamedGroup: X25519MLKEM768") == hybrid, "the hybrid group was offered");
	// the default offer includes it, and the peer accepts that too
	{
		Session s;
		defer s.close();
		s.open("trace13", with_ca(), "localhost")!!;
		s.t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!!;
		char[16] buf;
		s.t.read(&buf, 5 * time::SEC)!!;
	}
	usz after = hybrid;
	for (int i = 0; i < 40 && after == hybrid; i++)
	{
		thread::sleep_ms(50)!!;
		after = peer_support::log_count("trace13", "NamedGroup: X25519MLKEM768");
	}
	assert(after > hybrid);
}
