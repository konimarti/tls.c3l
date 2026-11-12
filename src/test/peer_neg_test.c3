module tls::peer_neg_test;

import tls;
import tls::peer_support;
import std::time, std::io, std::thread, std::encoding::hex;

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

// Alerts the peer RECEIVED from our client with the given description, e.g. "fatal certificate_expired". The peers of
// the negative scenarios run with -msg, which marks messages they receive with "<<<" and the ones they send with ">>>";
// only the former count, so neither the alerts a peer sends itself nor the noise of the harness's readiness probe do.
fn usz alerts_from_client(String scenario, String description)
{
	String path = peer_support::state_value("OUT").tconcat("/").tconcat(scenario).tconcat(".log");
	if (!file::is_file(path)) return 0;
	String text = (String)file::load_temp(path)!!;
	usz count = 0;
	foreach (line : text.tsplit("\n"))
	{
		if (line.starts_with("<<<") && line.contains("Alert") && line.contains(description)) count++;
	}
	return count;
}

// The peer prints its messages a moment after receiving them.
fn bool wait_for_client_alert(String scenario, String description, usz before)
{
	for (int i = 0; i < 40; i++)
	{
		if (alerts_from_client(scenario, description) > before) return true;
		thread::sleep_ms(50)!!;
	}
	return false;
}

// The handshake against `scenario` must fail with `want`, the engine must report `code` as the verification result, and
// the peer must have received exactly the alert `alert` from us (not just any alert, and not its own).
//
// The peers are `openssl s_server`, which serves ONE connection at a time: a test must close its connection before
// it opens the next one to the same peer, or the second waits until its timeout.
fn void expect_failure(String scenario, String name, fault want, long code, String alert)
{
	usz before = alerts_from_client(scenario, alert);
	Probe p;
	defer p.release();
	p.start(scenario, trusting_the_test_ca(), name);
	assert(!p.done, "the handshake with %s succeeded", scenario);
	assert(p.result == want, "%s: fault %s, wanted %s", scenario, p.result, want);
	assert(p.conn.verify_result() == code, "%s: verify result %d, wanted %d", scenario, p.conn.verify_result(), code);
	assert(wait_for_client_alert(scenario, alert, before), "%s: the peer did not receive %s from us", scenario, alert);
}

// ---- certificate problems seen by a real server ----

fn void test_peer_neg_expired_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("expired", "localhost", tls::CERT_EXPIRED, 10, "fatal certificate_expired");
}

fn void test_peer_neg_certificate_not_yet_valid() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("notyet", "localhost", tls::CERT_NOT_YET_VALID, 9, "fatal bad_certificate");
}

fn void test_peer_neg_wrong_host_name() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("wronghost", "localhost", tls::HOSTNAME_MISMATCH, 62, "fatal bad_certificate");
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
	expect_failure("untrusted", "localhost", tls::CERT_UNTRUSTED, 20, "fatal unknown_ca");
}

fn void test_peer_neg_self_signed_certificate() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("selfsigned", "localhost", tls::CERT_SELF_SIGNED, 18, "fatal unknown_ca");
}

fn void test_peer_neg_certificate_for_another_purpose() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("noeku", "localhost", tls::CERT_INVALID, 26, "fatal unsupported_certificate");
}

fn void test_peer_neg_intermediate_that_is_not_a_ca() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("badint", "localhost", tls::CERT_INVALID, 79, "fatal unknown_ca");
}

fn void test_peer_neg_common_name_alone_is_not_enough() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("cnonly", "test.example", tls::HOSTNAME_MISMATCH, 62, "fatal bad_certificate");
}

fn void test_peer_neg_dns_name_in_the_certificate_for_an_address() @test
{
	if (!peer_support::peers_ready()) return;
	expect_failure("dnsonly", "127.0.0.1", tls::HOSTNAME_MISMATCH, 64, "fatal bad_certificate");
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
	expect_failure("wildcard", "a.b.test.example", tls::HOSTNAME_MISMATCH, 62, "fatal bad_certificate");
	expect_failure("wildcard", "test.example", tls::HOSTNAME_MISMATCH, 62, "fatal bad_certificate");
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
	Probe p;
	defer p.release();
	p.start("tls11", trusting_the_test_ca(), "localhost");
	assert(!p.done);
	assert(p.result == tls::PROTOCOL_VERSION, "fault %s", p.result);
	// the server said so itself: protocol_version (70)
	assert(p.conn.last_alert == 70, "alert %d", p.conn.last_alert);
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
	// 66: EE key too small, 68: CA signature digest too weak (observed on OpenSSL 3.5.5)
	expect_failure("weakkey", "localhost", tls::CERT_INVALID, 66, "fatal bad_certificate");
	expect_failure("sha1sig", "localhost", tls::CERT_INVALID, 68, "fatal bad_certificate");
}

// ---- nothing bad gets through ----

// Only a smoke test: the default settings trust the system store, which does not hold the test CA, so every peer here
// fails with an unknown issuer whatever else is wrong with it. The checks themselves (expiry, name, purpose, key
// strength) are covered by the tests above, which trust the test CA.
fn void test_peer_neg_system_store_alone_refuses_every_test_peer() @test
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

fn char[] selfsigned_fingerprint() => hex::tdecode(peer_support::state_value("SHA256_selfsigned"))!!;

fn void test_peer_neg_pinned_self_signed_peer_is_accepted_under_any_name() @test
{
	if (!peer_support::peers_ready()) return;
	char[] pin = selfsigned_fingerprint();
	ClientConfig cfg = { .verify = PINNED_ONLY, .pin_sha256 = pin };
	String[3] names = { "localhost", "no-such-name.example", "10.9.8.7" };
	foreach (name : names)
	{
		Probe p;
		defer p.release();
		p.start("selfsigned", cfg, name);
		assert(p.done, "name %s: fault %s", name, p.result);
	}
}

fn void test_peer_neg_pin_that_does_not_match_is_refused() @test
{
	if (!peer_support::peers_ready()) return;
	char[32] wrong;
	wrong[..] = selfsigned_fingerprint()[..];
	wrong[31] ^= 1;
	ClientConfig cfg = { .verify = PINNED_ONLY, .pin_sha256 = wrong[..] };
	Probe p;
	defer p.release();
	p.start("selfsigned", cfg, "localhost");
	assert(!p.done);
	assert(p.result == tls::PIN_MISMATCH, "fault %s", p.result);
	assert(p.conn.out_pending() == 0);
}
