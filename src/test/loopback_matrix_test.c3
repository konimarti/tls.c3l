module tls::loopback_matrix_test;

import tls;
import tls::loopback;
import tls::ossl;
import std::io;

// A client verifying `name` against a server that presents `cert` (chain files carry their own key name).
// Expects the client to fail with `want`, to report the raw verification result `code`, and the text of that code to contain `text`.
fn void expect_verify_failure(String cert_file, String key_file, String name, fault want, long code, String text)
{
	ServerConfig sc = { .cert_file = loopback::pki(cert_file), .key_file = loopback::pki(key_file) };
	Pair p;
	p.open(loopback::client_cfg(), sc, name);
	defer p.close();
	assert(!p.outcome.client_done);
	assert(p.outcome.client_fault == want);
	assert(p.c.verify_result() == code, "verify result %d, wanted %d", p.c.verify_result(), code);
	String message = (String)((ZString)ossl::x509_verify_cert_error_string((CLong)code)).str_view();
	assert(loopback::contains_text(message, text));
	// the peer is told why: the server ends with the alert it received
	assert(p.outcome.server_fault == tls::ALERT_RECEIVED);
}

fn void expect_name_ok(String cert, String name)
{
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg(cert), name);
	defer p.close();
	assert(p.outcome.client_done);
	assert(!p.outcome.client_fault);
	assert(p.c.verify_result() == 0);
}

fn void expect_name_mismatch(String cert, String name, long code)
{
	Pair p;
	p.open(loopback::client_cfg(), loopback::server_cfg(cert), name);
	defer p.close();
	assert(!p.outcome.client_done);
	assert(p.outcome.client_fault == tls::HOSTNAME_MISMATCH);
	assert(p.c.verify_result() == code);
}

// ---- verification results ----

fn void test_verify_expired() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("expired.pem", "expired.key", "localhost", tls::CERT_EXPIRED, 10, "expired");
}

fn void test_verify_not_yet_valid() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("notyet.pem", "notyet.key", "localhost", tls::CERT_NOT_YET_VALID, 9, "not yet valid");
}

fn void test_verify_self_signed_leaf() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("selfsigned.pem", "selfsigned.key", "localhost", tls::CERT_SELF_SIGNED, 18, "self-signed");
}

fn void test_verify_unknown_issuer() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("untrusted.pem", "untrusted.key", "localhost", tls::CERT_UNTRUSTED, 20, "issuer");
}

fn void test_verify_untrusted_root_in_chain() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("untrusted-chain.pem", "untrusted.key", "localhost", tls::CERT_SELF_SIGNED, 19, "chain");
}

fn void test_verify_name_mismatch() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("wronghost.pem", "wronghost.key", "localhost", tls::HOSTNAME_MISMATCH, 62, "mismatch");
}

fn void test_verify_ip_mismatch() @test
{
	if (!loopback::pki_ready()) return;
	// the certificate names 127.0.0.1, the client asks for another address
	expect_verify_failure("server.pem", "server.key", "127.0.0.2", tls::HOSTNAME_MISMATCH, 64, "ip address mismatch");
}

fn void test_verify_certificate_for_another_purpose() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("wrong-eku.pem", "wrong-eku.key", "localhost", tls::CERT_INVALID, 26, "purpose");
}

fn void test_verify_intermediate_that_is_not_a_ca() @test
{
	if (!loopback::pki_ready()) return;
	expect_verify_failure("bad-intermediate-chain.pem", "bad-leaf.key", "localhost", tls::CERT_INVALID, 79, "invalid ca");
}

fn void test_weak_server_certificates_are_refused_when_loaded() @test
{
	if (!loopback::pki_ready()) return;
	// observed on OpenSSL 3.5.5: at the default security level neither a 1024-bit RSA key nor a SHA-1 signature is accepted
	ServerConfig weak_key = loopback::server_cfg("rsa1024");
	assert(@catch(tls::new_server_context(&weak_key)) == tls::CERT_LOAD_FAILED);
	ServerConfig weak_signature = loopback::server_cfg("sha1-signed");
	assert(@catch(tls::new_server_context(&weak_signature)) == tls::CERT_LOAD_FAILED);
}

// ---- host names ----

fn void test_host_h1_exact_name() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_ok("server", "test.example");
}

fn void test_host_h2_case_is_ignored() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_ok("server", "TEST.EXAMPLE");
}

fn void test_host_h3_wildcard_matches_one_label() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_ok("wildcard", "a.test.example");
}

fn void test_host_h4_wildcard_does_not_span_labels() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("wildcard", "a.b.test.example", 62);
}

fn void test_host_h5_wildcard_does_not_match_the_parent() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("wildcard", "test.example", 62);
}

fn void test_host_h7_partial_wildcard_is_refused() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("partial-wildcard", "foobar.test.example", 62);
}

fn void test_host_h8_dns_name_never_matches_an_address() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("dns-only", "127.0.0.1", 64);
}

fn void test_host_h9_ip_address_in_the_certificate() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_ok("ip-only", "127.0.0.1");
	// and a name cannot use it
	expect_name_mismatch("ip-only", "localhost", 62);
}

fn void test_host_h10_address_checked_as_a_name() @test
{
	if (!loopback::pki_ready()) return;
	// an address string given to OpenSSL through the host name entry point; we never do that, this pins what it does
	ClientConfig cc = loopback::client_cfg();
	cc.verify = CHAIN_ONLY;
	Context cctx = tls::new_client_context(&cc)!!;
	defer cctx.free();
	ServerConfig sc = loopback::server_cfg("ip-only");
	Context sctx = tls::new_server_context(&sc)!!;
	defer sctx.free();
	Conn c = cctx.new_client_conn("127.0.0.1")!!;
	defer c.free();
	Conn s = sctx.new_server_conn()!!;
	defer s.free();
	assert(ossl::ssl_set1_host(c.ssl, "127.0.0.1") == 1);
	Link link;
	Outcome o = loopback::run_handshake(&c, &s, &link);
	// observed on OpenSSL 3.5.5: an address string given to the host name entry point is matched against the
	// certificate's IP addresses, so the handshake succeeds; our code uses the explicit IP entry point regardless
	assert(o.client_done);
	assert(!o.client_fault);
	assert(c.verify_result() == 0);
}

fn void test_host_h11_common_name_alone_is_not_enough() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("cn-only", "test.example", 62);
}

fn void test_host_h12_common_name_is_ignored_when_names_exist() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_mismatch("cn-other", "other", 62);
	expect_name_ok("cn-other", "test.example");
}

fn void test_host_h13_name_with_an_embedded_nul() @test
{
	if (!loopback::pki_ready()) return;
	// the certificate names "evil.com\0.good.com": neither half may match
	expect_name_mismatch("nul-san", "evil.com", 62);
	expect_name_mismatch("nul-san", "good.com", 62);
}

fn void test_host_h14_trailing_dot_is_ignored() @test
{
	if (!loopback::pki_ready()) return;
	expect_name_ok("server", "test.example.");
}

fn void test_host_name_checks_skipped_in_chain_only_mode() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.verify = CHAIN_ONLY;
	String[3] certs = { "wildcard", "dns-only", "cn-only" };
	String[3] names = { "a.b.test.example", "127.0.0.1", "test.example" };
	foreach (i, cert : certs)
	{
		Pair p;
		p.open(cc, loopback::server_cfg(cert), names[i]);
		defer p.close();
		assert(p.outcome.client_done);
		assert(!p.outcome.client_fault);
	}
}
