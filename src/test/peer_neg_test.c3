module tls::peer_neg_test;

import tls;
import tls::peer_support;
import std::time, std::io, std::thread;

// A client connection driven by hand over TCP, so the test can look at the engine after a failure
// (the transport adapter frees it when a connect fails).
struct Probe
{
	Context ctx;
	TcpTransport tcp;
	Conn conn;
	bool done;
	fault result;
}

fn void Probe.start(&self, String scenario, ClientConfig cfg, String name)
{
	self.ctx = tls::new_client_context(&cfg)!!;
	self.tcp = tls::tcp_connect("127.0.0.1", peer_support::peer_port(scenario), 5 * time::SEC)!!;
	self.conn = self.ctx.new_client_conn(name)!!;
	self.run_handshake();
}

fn void Probe.release(&self)
{
	(void)self.tcp.close();
	self.conn.free();
	self.ctx.free();
}

// Sends what the engine has queued; the peer may already be gone, which does not matter here.
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

// Takes one read from the network into the engine. False when nothing more will come.
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

fn ClientConfig trusting_the_test_ca()
{
	return { .ca_file = peer_support::ca_file() };
}

// The messages the peer has printed that mention an alert (the peers of the negative scenarios run with -msg).
fn usz alerts_seen(String scenario)
{
	String path = peer_support::state_value("OUT").tconcat("/").tconcat(scenario).tconcat(".log");
	if (!file::is_file(path)) return 0;
	String text = (String)file::load_temp(path)!!;
	usz count = 0;
	foreach (part : text.tsplit("Alert")) count++;
	return count - 1;
}

// The handshake against `scenario` must fail with `want` and the engine must report `code` as the verification result.
fn void expect_failure(String scenario, String name, fault want, long code)
{
	usz alerts = alerts_seen(scenario);
	Probe p;
	defer p.release();
	p.start(scenario, trusting_the_test_ca(), name);
	assert(!p.done, "the handshake with %s succeeded", scenario);
	assert(p.result == want, "%s: fault %s, wanted %s", scenario, p.result, want);
	assert(p.conn.verify_result() == code, "%s: verify result %d, wanted %d", scenario, p.conn.verify_result(), code);
	// the failure ended with an alert to the peer, not with silence
	assert(wait_for_alert(scenario, alerts), "%s: the peer saw no alert", scenario);
}

// The peer prints its messages a moment after receiving them.
fn bool wait_for_alert(String scenario, usz before)
{
	for (int i = 0; i < 40; i++)
	{
		if (alerts_seen(scenario) > before) return true;
		thread::sleep_ms(50)!!;
	}
	return false;
}

// ---- certificate problems seen by a real server ----

fn void test_peer_neg_expired_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("expired", "localhost", tls::CERT_EXPIRED, 10);
}

fn void test_peer_neg_certificate_not_yet_valid() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("notyet", "localhost", tls::CERT_NOT_YET_VALID, 9);
}

fn void test_peer_neg_wrong_host_name() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("wronghost", "localhost", tls::HOSTNAME_MISMATCH, 62);
}

fn void test_peer_neg_wrong_host_name_passes_without_the_name_check() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = trusting_the_test_ca();
	cfg.verify = CHAIN_ONLY;
	Probe p;
	defer p.release();
	p.start("wronghost", cfg, "localhost");
	assert(p.done);
	assert(p.conn.verify_result() == 0);
}

fn void test_peer_neg_issuer_not_trusted() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("untrusted", "localhost", tls::CERT_UNTRUSTED, 20);
}

fn void test_peer_neg_self_signed_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("selfsigned", "localhost", tls::CERT_SELF_SIGNED, 18);
}

fn void test_peer_neg_certificate_for_another_purpose() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("noeku", "localhost", tls::CERT_INVALID, 26);
}

fn void test_peer_neg_intermediate_that_is_not_a_ca() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("badint", "localhost", tls::CERT_INVALID, 79);
}

fn void test_peer_neg_common_name_alone_is_not_enough() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("cnonly", "test.example", tls::HOSTNAME_MISMATCH, 62);
}

fn void test_peer_neg_dns_name_in_the_certificate_for_an_address() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("dnsonly", "127.0.0.1", tls::HOSTNAME_MISMATCH, 64);
}

fn void test_peer_neg_wildcard_matches_one_label_only() @test
{
	if (!peer_support::peers_ready()) return;
	Probe p;
	{
		defer p.release();
		p.start("wildcard", trusting_the_test_ca(), "a.test.example");
		assert(p.done);
	}
	expect_failure("wildcard", "a.b.test.example", tls::HOSTNAME_MISMATCH, 62);
	expect_failure("wildcard", "test.example", tls::HOSTNAME_MISMATCH, 62);
}

fn void test_peer_neg_insecure_mode_accepts_an_expired_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = { .verify = INSECURE_NONE };
	Probe p;
	defer p.release();
	p.start("expired", cfg, "localhost");
	assert(p.done);
	assert(!p.result);
}

// ---- protocol versions ----

fn void test_peer_neg_server_that_only_speaks_tls11() @test
{
	if (!peer_support::peers_ready()) return;
	usz alerts = alerts_seen("tls11");
	Probe p;
	defer p.release();
	p.start("tls11", trusting_the_test_ca(), "localhost");
	assert(!p.done);
	assert(p.result == tls::PROTOCOL_VERSION, "fault %s", p.result);
	assert(wait_for_alert("tls11", alerts));
}

// ---- client certificates ----

fn void test_peer_neg_missing_client_certificate_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	// TLS 1.3: the client believes it is done; the server's alert arrives with the first read
	Probe p;
	defer p.release();
	p.start("mtls-wrongca", trusting_the_test_ca(), "localhost");
	assert(p.done, "fault %s", p.result);
	p.read_for_a_while();
	assert(p.result == tls::ALERT_RECEIVED, "fault %s", p.result);
	assert(p.conn.last_alert == 116, "alert %d", p.conn.last_alert); // certificate_required
}

fn void test_peer_neg_client_certificate_from_the_wrong_ca() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig cfg = trusting_the_test_ca();
	cfg.client_cert_file = peer_support::pki_file("untrusted.pem");
	cfg.client_key_file = peer_support::pki_file("untrusted.key");
	Probe p;
	defer p.release();
	p.start("mtls-wrongca", cfg, "localhost");
	assert(p.done, "fault %s", p.result);
	p.read_for_a_while();
	assert(p.result == tls::ALERT_RECEIVED, "fault %s", p.result);
	assert(p.conn.last_alert == 48, "alert %d", p.conn.last_alert); // unknown_ca
}

fn void test_peer_neg_missing_client_certificate_tls12() @test
{
	if (!peer_support::peers_ready()) return;
	// TLS 1.2: the refusal is part of the handshake
	Probe p;
	defer p.release();
	p.start("mtls12", trusting_the_test_ca(), "localhost");
	assert(!p.done);
	assert(p.result == tls::ALERT_RECEIVED, "fault %s", p.result);
	assert(p.conn.last_alert == 40, "alert %d", p.conn.last_alert); // handshake_failure
}

// ---- weak certificates, seen by the client ----

fn void test_peer_neg_weak_rsa_key_and_sha1_signature() @test
{
	if (!peer_support::peers_ready()) return;
	String[2] scenarios = { "weakkey", "sha1sig" };
	foreach (scenario : scenarios)
	{
		Probe p;
		defer p.release();
		p.start(scenario, trusting_the_test_ca(), "localhost");
		assert(!p.done, "%s: handshake succeeded", scenario);
		assert(p.result == tls::CERT_INVALID, "%s: fault %s, verify result %d", scenario, p.result, p.conn.verify_result());
	}
}

// ---- nothing bad gets through ----

fn void test_peer_neg_default_settings_never_accept_a_bad_peer() @test
{
	if (!peer_support::peers_ready()) return;
	String[14] bad = { "expired", "notyet", "wronghost", "untrusted", "selfsigned", "noeku", "badint", "cnonly",
	                   "dnsonly", "weakkey", "sha1sig", "tls11", "wildcard", "mtls12" };
	foreach (scenario : bad)
	{
		ClientConfig cfg;
		Probe p;
		defer p.release();
		// the default configuration trusts the system store only: none of these chains to it
		String name = scenario == "cnonly" ? "test.example" : "localhost";
		p.start(scenario, cfg, name);
		assert(!p.done, "%s was accepted with the default settings", scenario);
		assert(p.result, "%s: no fault", scenario);
	}
}
