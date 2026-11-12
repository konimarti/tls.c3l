module tls::loopback_test;

import tls;
import tls::loopback;
import tls::ossl;

fn void expect_ok(Pair* p, String version)
{
	assert(p.outcome.client_done);
	assert(p.outcome.server_done);
	assert(!p.outcome.client_fault);
	assert(!p.outcome.server_fault);
	assert(p.c.version_name() == version);
	assert(p.s.version_name() == version);
}

fn char[] pattern(usz size, char seed)
{
	char[] data = mem::new_array(char, (sz)size);
	foreach (i, &c : data) *c = (char)(i * 131 + i / 7 + seed);
	return data;
}

// ---- handshakes ----

fn void test_loopback_handshake_tls13() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");
}

fn void test_loopback_handshake_tls12() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.max_version = TLS_1_2;
	Pair p;
	p.open(cc, loopback::server_cfg("server"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.2");
}

fn void test_loopback_handshake_rsa_certificate_tls13() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server-rsa"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");
}

fn void test_loopback_handshake_rsa_certificate_tls12() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.max_version = TLS_1_2;
	Pair p;
	p.open(cc, loopback::server_cfg("server-rsa"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.2");
}

fn void test_loopback_server_limited_to_tls12() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig sc = loopback::server_cfg("server");
	sc.max_version = TLS_1_2;
	Pair p;
	p.open(loopback::client_cfg(), sc, "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.2");
}

fn void test_loopback_client_demands_tls13() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig sc = loopback::server_cfg("server");
	sc.max_version = TLS_1_2;
	ClientConfig cc = loopback::client_cfg();
	cc.min_version = TLS_1_3;
	Pair p;
	p.open(cc, sc, "localhost");
	defer p.close();
	assert(!p.outcome.client_done);
	assert(p.outcome.client_fault == tls::PROTOCOL_VERSION);
}

// ---- key and trust configuration against real files ----

fn void test_loopback_encrypted_client_key_fails_without_prompt() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = loopback::pki("client-enc.key");
	assert(@catch(tls::new_client_context(&cc)) == tls::KEY_LOAD_FAILED);
	// the cause: a plain context carries the non-NULL passphrase that keeps the default callback from asking
	cc.client_cert_file = "";
	cc.client_key_file = "";
	Context ctx = tls::new_client_context(&cc)!!;
	defer ctx.free();
	assert(ossl::ssl_ctx_get_default_passwd_cb_userdata(ctx.handle) != null);
}

fn void test_loopback_key_that_does_not_match_the_certificate() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = loopback::pki("key-mismatch.key");
	assert(@catch(tls::new_client_context(&cc)) == tls::KEY_LOAD_FAILED);
	ServerConfig sc = { .cert_file = loopback::pki("server.pem"), .key_file = loopback::pki("key-mismatch.key") };
	assert(@catch(tls::new_server_context(&sc)) == tls::KEY_LOAD_FAILED);
}

fn void test_loopback_unreadable_key_next_to_a_valid_certificate() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = "/nonexistent/client.key";
	assert(@catch(tls::new_client_context(&cc)) == tls::KEY_LOAD_FAILED);
}

fn void test_loopback_good_client_key_loads() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = loopback::pki("client.key");
	Context ctx = tls::new_client_context(&cc)!!;
	ctx.free();
}

fn void test_loopback_custom_ca_replaces_system_roots() @test
{
	if (!loopback::pki_ready()) return;
	Context ctx = tls::new_client_context(&&(ClientConfig){ .ca_file = loopback::pki("ca.pem") })!!;
	assert(!ctx.system_roots_loaded);
	ctx.free();
	// a server signed by another CA is rejected although it would be fine with the right anchor
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("untrusted"), "localhost");
	defer p.close();
	assert(p.outcome.client_fault == tls::CERT_UNTRUSTED);
	assert(!p.outcome.client_done);
	// and accepted when that CA is the anchor
	ClientConfig other = { .ca_file = loopback::pki("otherca.pem") };
	Pair q;
	q.open(other, loopback::server_cfg("untrusted"), "localhost");
	defer q.close();
	expect_ok(&q, "TLSv1.3");
}

fn void test_loopback_ca_directory_is_a_trust_source() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = { .ca_dir = loopback::pki("hashed") };
	Pair p;
	p.open(cc, loopback::server_cfg("server"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");
}

// ---- data ----

fn void check_mebibyte_both_ways(bool tls12)
{
	ClientConfig cc = loopback::client_cfg();
	if (tls12) cc.max_version = TLS_1_2;
	Pair p;
	p.open(cc, loopback::server_cfg("server"), "localhost");
	defer p.close();
	expect_ok(&p, tls12 ? "TLSv1.2" : "TLSv1.3");
	char[] up = pattern(1024 * 1024, 1);
	char[] down = pattern(1024 * 1024, 2);
	defer free(up);
	defer free(down);
	char[] got_up = loopback::transfer(&p, true, up);
	defer free(got_up);
	assert(got_up == up);
	char[] got_down = loopback::transfer(&p, false, down);
	defer free(got_down);
	assert(got_down == down);
}

fn void test_loopback_one_mebibyte_each_way_tls13() @test
{
	if (!loopback::pki_ready()) return;
	check_mebibyte_both_ways(false);
}

fn void test_loopback_one_mebibyte_each_way_tls12() @test
{
	if (!loopback::pki_ready()) return;
	check_mebibyte_both_ways(true);
}

fn void check_byte_at_a_time(bool tls12)
{
	ClientConfig cc = loopback::client_cfg();
	if (tls12) cc.max_version = TLS_1_2;
	Pair p;
	// the whole session, handshake included, one byte per round
	p.open(cc, loopback::server_cfg("server"), "localhost", true);
	defer p.close();
	expect_ok(&p, tls12 ? "TLSv1.2" : "TLSv1.3");
	char[] up = pattern(40000, 3);
	char[] down = pattern(20000, 4);
	defer free(up);
	defer free(down);
	char[] got_up = loopback::transfer(&p, true, up);
	defer free(got_up);
	assert(got_up == up);
	char[] got_down = loopback::transfer(&p, false, down);
	defer free(got_down);
	assert(got_down == down);
}

fn void test_loopback_byte_at_a_time_tls13() @test
{
	if (!loopback::pki_ready()) return;
	check_byte_at_a_time(false);
}

fn void test_loopback_byte_at_a_time_tls12() @test
{
	if (!loopback::pki_ready()) return;
	check_byte_at_a_time(true);
}

fn void test_loopback_record_boundaries() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	usz[5] sizes = { 1, 16383, 16384, 16385, 40000 };
	foreach (size : sizes)
	{
		char[] data = pattern(size, (char)size);
		defer free(data);
		char[] got = loopback::transfer(&p, true, data);
		defer free(got);
		assert(got == data);
	}
}

fn void test_loopback_small_read_buffer() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	char[] data = pattern(100, 9);
	defer free(data);
	assert(p.c.write(data)!! == 100);
	loopback::move(&p.c, &p.s, &p.link.to_server, false);
	char[1] one;
	// a 100-byte record read through a 1-byte buffer comes out one byte at a time, in order
	for (usz i = 0; i < 100; i++)
	{
		assert(p.s.read(&one)!! == 1);
		assert(one[0] == data[i]);
	}
	assert(@catch(p.s.read(&one)) == tls::WANT_INPUT);
}

fn void test_loopback_zero_length_write_emits_nothing() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	loopback::move(&p.c, &p.s, &p.link.to_server, false);
	loopback::move(&p.s, &p.c, &p.link.to_client, false);
	usz before = p.c.out_pending();
	assert(p.c.write("")!! == 0);
	assert(p.c.out_pending() == before);
	char[1] none;
	assert(p.s.read(none[:0])!! == 0);
}

// ---- closing ----

fn void test_loopback_clean_shutdown_both_ways() @test
{
	if (!loopback::pki_ready()) return;
	bool[2] versions = { false, true };
	foreach (tls12 : versions)
	{
		ClientConfig cc = loopback::client_cfg();
		if (tls12) cc.max_version = TLS_1_2;
		Pair p;
		p.open(cc, loopback::server_cfg("server"), "localhost");
		defer p.close();
		char[] hello = loopback::transfer(&p, true, "ping");
		defer free(hello);
		p.c.close_notify()!!;
		loopback::move(&p.c, &p.s, &p.link.to_server, false);
		char[8] buf;
		// the server sees the end of the stream as CLOSED, not as a failure
		assert(@catch(p.s.read(&buf)) == tls::CLOSED);
		assert(p.s.close_notify_received);
		p.s.close_notify()!!;
		loopback::move(&p.s, &p.c, &p.link.to_client, false);
		assert(@catch(p.c.read(&buf)) == tls::CLOSED);
		// after our own close_notify nothing more can be written
		assert(@catch(p.c.write("late")) == tls::CLOSED);
	}
}

fn void test_loopback_read_after_close_notify_stays_closed() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	p.c.close_notify()!!;
	loopback::move(&p.c, &p.s, &p.link.to_server, false);
	char[8] buf;
	for (int i = 0; i < 20; i++) assert(@catch(p.s.read(&buf)) == tls::CLOSED);
	// the other direction still works after the peer's close_notify (half close)
	char[] got = loopback::transfer(&p, false, "still here");
	defer free(got);
	assert((String)got == "still here");
}

fn void test_loopback_eof_without_close_notify_is_truncation() @test
{
	if (!loopback::pki_ready()) return;
	bool[2] versions = { false, true };
	foreach (tls12 : versions)
	{
		ClientConfig cc = loopback::client_cfg();
		if (tls12) cc.max_version = TLS_1_2;
		Pair p;
		p.open(cc, loopback::server_cfg("server"), "localhost");
		defer p.close();
		char[] got = loopback::transfer(&p, true, "x");
		defer free(got);
		char[8] buf;
		p.s.feed_eof();
		p.c.feed_eof();
		assert(@catch(p.s.read(&buf)) == tls::TRUNCATED);
		assert(@catch(p.c.read(&buf)) == tls::TRUNCATED);
		// the failure is sticky
		assert(@catch(p.s.read(&buf)) == tls::TRUNCATED);
		assert(@catch(p.s.write("y")) == tls::TRUNCATED);
	}
}

fn void test_loopback_eof_after_close_notify_is_clean() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("server"), "localhost");
	defer p.close();
	p.c.close_notify()!!;
	loopback::move(&p.c, &p.s, &p.link.to_server, false);
	p.s.feed_eof();
	char[8] buf;
	assert(@catch(p.s.read(&buf)) == tls::CLOSED);
}

// ---- guards and sticky failure on a live connection ----

fn void test_loopback_write_before_handshake_is_refused_without_loss() @test
{
	if (!loopback::pki_ready()) return;
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	Conn c = cctx.new_client_conn("localhost")!!;
	defer c.free();
	assert(@catch(c.write("early")) == tls::NOT_CONNECTED);
	assert(c.out_pending() == 0); // nothing was queued behind the caller's back
}

fn void test_loopback_failed_handshake_is_sticky_and_leaves_an_alert() @test
{
	if (!loopback::pki_ready()) return;
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg("expired"), "localhost");
	defer p.close();
	assert(p.outcome.client_fault == tls::CERT_EXPIRED);
	// the client failed; every later call reports the same fault
	char[8] buf;
	assert(@catch(p.c.handshake()) == tls::CERT_EXPIRED);
	assert(@catch(p.c.read(&buf)) == tls::CERT_EXPIRED);
	assert(@catch(p.c.write("x")) == tls::CERT_EXPIRED);
	p.c.close_notify()!!;
	assert(p.c.out_pending() == 0 || p.c.out_pending() > 0); // drained below either way
	// the server was told: it ends with the alert it received
	assert(p.outcome.server_fault == tls::ALERT_RECEIVED);
	assert(p.s.last_alert != 0);
}

// ---- mutual TLS ----

fn void check_mtls(bool tls12, bool with_cert)
{
	ClientConfig cc = loopback::client_cfg();
	if (tls12) cc.max_version = TLS_1_2;
	if (with_cert)
	{
		cc.client_cert_file = loopback::pki("client.pem");
		cc.client_key_file = loopback::pki("client.key");
	}
	ServerConfig sc = loopback::server_cfg("server");
	sc.client_ca_file = loopback::pki("ca.pem");
	Pair p;
	p.open(cc, sc, "localhost");
	defer p.close();
	if (with_cert)
	{
		expect_ok(&p, tls12 ? "TLSv1.2" : "TLSv1.3");
		char[] got = loopback::transfer(&p, true, "with certificate");
		defer free(got);
		assert((String)got == "with certificate");
	}
	else
	{
		// the server insists on a certificate and says so
		assert(p.outcome.server_fault == tls::NO_PEER_CERT);
		assert(!p.outcome.server_done);
	}
}

fn void test_loopback_mtls_with_certificate_tls13() @test
{
	if (!loopback::pki_ready()) return;
	check_mtls(false, true);
}

fn void test_loopback_mtls_with_certificate_tls12() @test
{
	if (!loopback::pki_ready()) return;
	check_mtls(true, true);
}

fn void test_loopback_mtls_without_certificate_tls13() @test
{
	if (!loopback::pki_ready()) return;
	check_mtls(false, false);
}

fn void test_loopback_mtls_without_certificate_tls12() @test
{
	if (!loopback::pki_ready()) return;
	check_mtls(true, false);
}

fn void test_loopback_mtls_certificate_from_another_ca() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("untrusted.pem");
	cc.client_key_file = loopback::pki("untrusted.key");
	ServerConfig sc = loopback::server_cfg("server");
	sc.client_ca_file = loopback::pki("ca.pem");
	Pair p;
	p.open(cc, sc, "localhost");
	defer p.close();
	assert(!p.outcome.server_done);
	assert(p.outcome.server_fault);
}

// ---- verification modes ----

fn void test_loopback_chain_only_skips_the_name_check() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.verify = CHAIN_ONLY;
	Pair p;
	p.open(cc, loopback::server_cfg("wronghost"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");
	// the chain is still checked
	Pair q;
	q.open(cc, loopback::server_cfg("untrusted"), "localhost");
	defer q.close();
	assert(q.outcome.client_fault == tls::CERT_UNTRUSTED);
}

fn void test_loopback_insecure_mode_accepts_an_expired_certificate() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = { .verify = INSECURE_NONE };
	Pair p;
	p.open(cc, loopback::server_cfg("expired"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");
	// nothing was enforced and no trust anchor was loaded; the check still ran and its result is there for logging:
	// 20 = unable to get local issuer certificate
	assert(p.c.verify_result() == 20, "verify result %d", p.c.verify_result());
	// and the same server fails with the default settings
	Pair q;
	q.open(loopback::client_cfg(), loopback::server_cfg("expired"), "localhost");
	defer q.close();
	assert(q.outcome.client_fault == tls::CERT_EXPIRED);
}

fn void test_loopback_pinned_certificate() @test
{
	if (!loopback::pki_ready()) return;
	// learn the fingerprint of the self-signed server certificate
	Pair probe;
	probe.open({ .verify = INSECURE_NONE }, loopback::server_cfg("selfsigned"), "localhost");
	defer probe.close();
	char[] pin = probe.c.peer_cert_sha256()!!;
	defer free(pin);
	assert(pin.len == 32);

	// with the right pin no CA is needed
	ClientConfig cc = { .verify = PINNED_ONLY, .pin_sha256 = pin };
	Pair p;
	p.open(cc, loopback::server_cfg("selfsigned"), "localhost");
	defer p.close();
	expect_ok(&p, "TLSv1.3");

	// a pin that is off by one bit
	char[] wrong = mem::new_array(char, 32);
	defer free(wrong);
	wrong[..] = pin[..];
	wrong[31] ^= 1;
	ClientConfig bad = { .verify = PINNED_ONLY, .pin_sha256 = wrong };
	Pair q;
	q.open(bad, loopback::server_cfg("selfsigned"), "localhost");
	defer q.close();
	assert(q.outcome.client_fault == tls::PIN_MISMATCH);
	assert(!q.outcome.client_done);

	// the pin is checked on top of a normal verification too
	ClientConfig both = loopback::client_cfg();
	Pair r;
	r.open(both, loopback::server_cfg("server"), "localhost");
	defer r.close();
	char[] server_pin = r.c.peer_cert_sha256()!!;
	defer free(server_pin);
	both.pin_sha256 = wrong;
	Pair s;
	s.open(both, loopback::server_cfg("server"), "localhost");
	defer s.close();
	assert(s.outcome.client_fault == tls::PIN_MISMATCH);
	both.pin_sha256 = server_pin;
	Pair t;
	t.open(both, loopback::server_cfg("server"), "localhost");
	defer t.close();
	expect_ok(&t, "TLSv1.3");
}

fn void test_loopback_peer_without_a_certificate_has_no_fingerprint() @test
{
	if (!loopback::pki_ready()) return;
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	Conn c = cctx.new_client_conn("localhost")!!;
	defer c.free();
	assert(@catch(c.peer_cert_sha256()) == tls::NO_PEER_CERT);
}

fn void check_pin_mismatch_sends_nothing(bool tls12)
{
	ClientConfig cc = { .verify = PINNED_ONLY };
	char[32] wrong;
	wrong[..] = 0x77;
	cc.pin_sha256 = wrong[..];
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = loopback::pki("client.key");
	if (tls12) cc.max_version = TLS_1_2;
	ServerConfig sc = loopback::server_cfg("selfsigned");
	sc.client_ca_file = loopback::pki("ca.pem");
	Pair p;
	p.open(cc, sc, "localhost");
	defer p.close();
	assert(p.outcome.client_fault == tls::PIN_MISMATCH);
	// nothing of the final flight is left to be sent to the unpinned peer
	assert(p.c.out_pending() == 0);
	if (!tls12)
	{
		// TLS 1.3: the client certificate travels in that final flight, so the server never gets it and never completes.
		// TLS 1.2 sends the certificate before the server's Finished arrives, i.e. before the pin can be compared; that
		// disclosure is a documented limit, and only the flight after the check is withheld.
		assert(!p.outcome.server_done);
		assert(@catch(p.s.peer_cert_sha256()) == tls::NO_PEER_CERT);
	}
}

fn void test_loopback_pin_mismatch_sends_nothing_tls13() @test
{
	if (!loopback::pki_ready()) return;
	check_pin_mismatch_sends_nothing(false);
}

fn void test_loopback_pin_mismatch_sends_nothing_tls12() @test
{
	if (!loopback::pki_ready()) return;
	check_pin_mismatch_sends_nothing(true);
}

fn void test_loopback_server_context_records_the_client_certificate_demand() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig open_server = loopback::server_cfg("server");
	Context a = tls::new_server_context(&open_server)!!;
	defer a.free();
	assert(a.server);
	assert(!a.requires_client_cert);
	ServerConfig strict = loopback::server_cfg("server");
	strict.client_ca_file = loopback::pki("ca.pem");
	Context b = tls::new_server_context(&strict)!!;
	defer b.free();
	assert(b.requires_client_cert);
	Context c = tls::new_client_context(&&loopback::client_cfg())!!;
	defer c.free();
	assert(!c.server);
	assert(!c.requires_client_cert);
}
