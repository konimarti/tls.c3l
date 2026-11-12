module tls::tests;

import tls;
import tls::ossl;
import libc;

// Config isolation test should run first to ensure OPENSSL_init_ssl runs with no config.
fn void test_01_config_isolation() @test
{
	libc::setenv("OPENSSL_CONF", "/nonexistent/openssl.cnf", 1);
	defer libc::unsetenv("OPENSSL_CONF");

	// init() must succeed even if OPENSSL_CONF points to a nonexistent file.
	if (catch err = ossl::init())
	{
		assert(false);
	}
}

fn void test_02_version() @test
{
	char* ver = ossl::openssl_version(0);
	assert(ver != null);
	String ver_str = ((ZString)ver).str_view();
	assert(ver_str.contains("OpenSSL 3."));
	assert(ossl::openssl_version_num() >= 0x30000000);
}

fn void test_03_ctx_ctrl() @test
{
	ossl::SslCtx* ctx = ossl::ssl_ctx_new(ossl::tls_client_method());
	assert(ctx != null);
	defer ossl::ssl_ctx_free(ctx);

	// Test min protocol set/get (0x0303 = TLS 1.2, ctrl 123/130)
	CLong set_min = ossl::ctx_set_min_proto(ctx, 0x0303);
	assert(set_min == 1);
	CLong get_min = ossl::ctx_get_min_proto(ctx);
	assert(get_min == 0x0303);

	// Test max protocol set/get (0x0304 = TLS 1.3, ctrl 124/131)
	CLong set_max = ossl::ctx_set_max_proto(ctx, 0x0304);
	assert(set_max == 1);
	CLong get_max = ossl::ctx_get_max_proto(ctx);
	assert(get_max == 0x0304);

	// Test groups set (ctrl 92)
	CLong set_grp = ossl::ctx_set_groups(ctx, "P-256");
	assert(set_grp == 1);

	// Test SNI set on SSL instance (ctrl 55)
	ossl::Ssl* s = ossl::ssl_new(ctx);
	assert(s != null);
	defer ossl::ssl_free(s);
	CLong sni_ret = ossl::set_sni(s, "localhost");
	assert(sni_ret == 1);

	// Test SSL_OP_NO_COMPRESSION and SSL_OP_NO_RENEGOTIATION
	ulong opts = ossl::ssl_ctx_set_options(ctx, ossl::SSL_OP_NO_COMPRESSION | ossl::SSL_OP_NO_RENEGOTIATION);
	assert((opts & ossl::SSL_OP_NO_COMPRESSION) != 0);
	assert((opts & ossl::SSL_OP_NO_RENEGOTIATION) != 0);
}

fn void test_04_memory_bio() @test
{
	ossl::BioMethod* bm = ossl::bio_s_mem();
	assert(bm != null);
	ossl::Bio* b = ossl::bio_new(bm);
	assert(b != null);
	defer ossl::bio_free(b);

	char[5] out = { 1, 2, 3, 4, 5 };
	CInt written = ossl::bio_write(b, &out, 5);
	assert(written == 5);
	assert(ossl::bio_ctrl_pending(b) == 5);

	char[5] in;
	CInt read_bytes = ossl::bio_read(b, &in, 5);
	assert(read_bytes == 5);
	assert(in == out);

	// Empty read returns <= 0 and BIO_FLAGS_SHOULD_RETRY is set
	char[1] empty_buf;
	CInt empty_read = ossl::bio_read(b, &empty_buf, 1);
	assert(empty_read <= 0);
	assert(ossl::bio_test_flags(b, ossl::BIO_FLAGS_SHOULD_RETRY) != 0);
}

fn void test_05_error_queue() @test
{
	ossl::SslCtx* ctx = ossl::ssl_ctx_new(ossl::tls_client_method());
	assert(ctx != null);
	defer ossl::ssl_ctx_free(ctx);

	// System error: nonexistent file -> errno 2 (ENOENT)
	ossl::err_clear_error();
	CInt r1 = ossl::ssl_ctx_load_verify_file(ctx, "/nonexistent");
	assert(r1 == 0);
	ulong e1 = ossl::err_peek_error();
	assert(e1 != 0);
	assert(ossl::err_is_system(e1));
	assert(ossl::err_errno(e1) == 2);

	char[256] buf;
	ulong taken1 = ossl::err_take(&buf);
	assert(taken1 == e1);
	assert(ossl::err_peek_error() == 0);

	// Parse error: garbage PEM file
	CInt r2 = ossl::ssl_ctx_load_verify_file(ctx, "src/test/fixtures/garbage.pem");
	assert(r2 == 0);
	ulong e2 = ossl::err_peek_error();
	assert(e2 != 0);
	assert(!ossl::err_is_system(e2));
	assert(ossl::err_lib(e2) != 0);

	ulong taken2 = ossl::err_take(&buf);
	assert(taken2 == e2);
	assert(ossl::err_peek_error() == 0);
}

fn bool verify_str_contains(CLong code, String needle)
{
	char* s = ossl::x509_verify_cert_error_string(code);
	if (s == null) return false;
	return ((ZString)s).str_view().to_lower_tcopy().contains(needle);
}

fn void test_06_verify_strings() @test
{
	assert(verify_str_contains(10, "expired"));
	assert(verify_str_contains(9, "not yet valid"));
	assert(verify_str_contains(18, "self"));
	assert(verify_str_contains(19, "chain"));
	assert(verify_str_contains(20, "issuer"));
	assert(verify_str_contains(62, "host"));
	assert(verify_str_contains(64, "ip"));
	assert(verify_str_contains(24, "ca"));
	assert(verify_str_contains(26, "purpose"));
}

fn void test_07_map_verify_code() @test
{
	assert(tls::map_verify_code(10) == tls::CERT_EXPIRED);
	assert(tls::map_verify_code(9) == tls::CERT_NOT_YET_VALID);
	assert(tls::map_verify_code(18) == tls::CERT_SELF_SIGNED);
	assert(tls::map_verify_code(19) == tls::CERT_SELF_SIGNED);
	assert(tls::map_verify_code(2) == tls::CERT_UNTRUSTED);
	assert(tls::map_verify_code(20) == tls::CERT_UNTRUSTED);
	assert(tls::map_verify_code(21) == tls::CERT_UNTRUSTED);
	assert(tls::map_verify_code(62) == tls::HOSTNAME_MISMATCH);
	assert(tls::map_verify_code(64) == tls::HOSTNAME_MISMATCH);
	assert(tls::map_verify_code(24) == tls::CERT_INVALID);
	assert(tls::map_verify_code(26) == tls::CERT_INVALID);
	assert(tls::map_verify_code(23) == tls::CERT_REVOKED);
	assert(tls::map_verify_code(9999) == tls::CERT_INVALID);
}

fn void test_08_verify_mode_constants() @test
{
	ossl::SslCtx* ctx = ossl::ssl_ctx_new(ossl::tls_client_method());
	assert(ctx != null);
	defer ossl::ssl_ctx_free(ctx);

	// Default is SSL_VERIFY_NONE (0)
	assert(ossl::ssl_ctx_get_verify_mode(ctx) == ossl::SSL_VERIFY_NONE);

	ossl::ssl_ctx_set_verify(ctx, ossl::SSL_VERIFY_PEER, null);
	assert(ossl::ssl_ctx_get_verify_mode(ctx) == ossl::SSL_VERIFY_PEER);

	ossl::ssl_ctx_set_verify(ctx, ossl::SSL_VERIFY_PEER | ossl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
	assert(ossl::ssl_ctx_get_verify_mode(ctx) == (ossl::SSL_VERIFY_PEER | ossl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT));
}

fn void test_09_reason_mapping() @test
{
	// Protocol version alert 70 -> reason 1070
	assert(tls::map_ssl_reason((20 << 23) | 1070, true) == tls::PROTOCOL_VERSION);

	// Received alert (unknown_ca = 48) -> reason 1048
	char alert_code = 0;
	assert(tls::map_ssl_reason((20 << 23) | 1048, true, &alert_code) == tls::ALERT_RECEIVED);
	assert(alert_code == 48);

	// Protocol version reasons
	assert(tls::map_ssl_reason((20 << 23) | 258, true) == tls::PROTOCOL_VERSION);
	assert(tls::map_ssl_reason((20 << 23) | 267, true) == tls::PROTOCOL_VERSION);
	assert(tls::map_ssl_reason((20 << 23) | 191, true) == tls::PROTOCOL_VERSION);
	assert(tls::map_ssl_reason((20 << 23) | 116, true) == tls::PROTOCOL_VERSION);

	// No shared cipher
	assert(tls::map_ssl_reason((20 << 23) | 193, true) == tls::NO_SHARED_CIPHER);

	// Truncated (unexpected eof)
	assert(tls::map_ssl_reason((20 << 23) | 294, false) == tls::TRUNCATED);

	// Protocol error (decryption failed, bad record mac, packet length too long)
	assert(tls::map_ssl_reason((20 << 23) | 147, false) == tls::PROTOCOL_ERROR);
	assert(tls::map_ssl_reason((20 << 23) | 281, false) == tls::PROTOCOL_ERROR);
	assert(tls::map_ssl_reason((20 << 23) | 198, false) == tls::PROTOCOL_ERROR);

	// Generic handshake failure vs openssl error
	assert(tls::map_ssl_reason((20 << 23) | 229, true) == tls::HANDSHAKE_FAILED);
	assert(tls::map_ssl_reason((20 << 23) | 999, true) == tls::HANDSHAKE_FAILED);
	assert(tls::map_ssl_reason((20 << 23) | 999, false) == tls::OPENSSL_ERROR);

	// Runtime verification of reason string
	char* reason_str = ossl::err_reason_error_string((20UL << 23) | 193);
	assert(reason_str != null);
	assert(((ZString)reason_str).str_view().contains("cipher"));
}

fn void test_10_map_ssl_error_order() @test
{
	assert(tls::map_ssl_error(ossl::SSL_ERROR_WANT_READ, null, true) == tls::WANT_INPUT);
	assert(tls::map_ssl_error(ossl::SSL_ERROR_ZERO_RETURN, null, true) == tls::CLOSED);
	assert(tls::map_ssl_error(ossl::SSL_ERROR_SYSCALL, null, true) == tls::TRUNCATED);
	assert(tls::map_ssl_error(ossl::SSL_ERROR_SSL, null, true) == tls::HANDSHAKE_FAILED);
	assert(tls::map_ssl_error(ossl::SSL_ERROR_SSL, null, false) == tls::OPENSSL_ERROR);
	assert(tls::map_ca_load_error(0) == tls::CA_LOAD_FAILED);
	assert(tls::map_cert_load_error(0) == tls::CERT_LOAD_FAILED);
	assert(tls::map_key_load_error(0) == tls::KEY_LOAD_FAILED);
}
