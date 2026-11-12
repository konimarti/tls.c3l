// The ONLY module that mentions OpenSSL. A pure-C3 backend replaces ossl.c3, errmap.c3 and engine.c3
// (config.c3 and adapter.c3 do not depend on OpenSSL).
// Every @cname symbol below must exist in libssl.so.3 / libcrypto.so.3: scripts/check-symbols.sh.
module tls::ossl;

alias CStr = char*; // NUL-terminated

struct SslCtx { char _opaque; }
struct Ssl { char _opaque; }
struct Bio { char _opaque; }
struct BioMethod { char _opaque; }
struct SslMethod { char _opaque; }
struct SslSession { char _opaque; }
struct SslCipher { char _opaque; }
struct X509Cert { char _opaque; }
struct X509VerifyParam { char _opaque; }
struct EvpMd { char _opaque; }

// Values from the public OpenSSL 3 headers, checked at runtime by the tests (read-back).
const CInt SSL_ERROR_NONE = 0;
const CInt SSL_ERROR_SSL = 1;
const CInt SSL_ERROR_WANT_READ = 2;
const CInt SSL_ERROR_WANT_WRITE = 3;
const CInt SSL_ERROR_SYSCALL = 5;
const CInt SSL_ERROR_ZERO_RETURN = 6;
const CInt SSL_VERIFY_NONE = 0;
const CInt SSL_VERIFY_PEER = 1;
const CInt SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;
const CInt TLS1_2_VERSION = 0x0303;
const CInt TLS1_3_VERSION = 0x0304;
// ctrl command numbers: the min/max protocol functions and the groups list are MACROS over *_ctrl in ssl.h.
const CInt SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
const CInt SSL_CTRL_SET_GROUPS_LIST = 92;
const CInt SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
const CInt SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
const CInt SSL_CTRL_GET_MIN_PROTO_VERSION = 130;
const CInt SSL_CTRL_GET_MAX_PROTO_VERSION = 131;
const CLong TLSEXT_NAMETYPE_HOST_NAME = 0;
const ulong SSL_OP_NO_COMPRESSION = 1UL << 17;
const ulong SSL_OP_NO_RENEGOTIATION = 1UL << 30;
const ulong OPENSSL_INIT_NO_LOAD_CONFIG = 0x80;
const CUInt X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4;
const CUInt X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x20;
const CInt BIO_FLAGS_SHOULD_RETRY = 0x8;
const CInt SSL_FILETYPE_PEM = 1;

extern fn CInt openssl_init_ssl(ulong opts, void* settings) @cname("OPENSSL_init_ssl");
extern fn CStr openssl_version(CInt which) @cname("OpenSSL_version");
extern fn ulong openssl_version_num() @cname("OpenSSL_version_num");
extern fn void openssl_cleanup() @cname("OPENSSL_cleanup");

extern fn SslMethod* tls_client_method() @cname("TLS_client_method");
extern fn SslMethod* tls_server_method() @cname("TLS_server_method");
extern fn SslCtx* ssl_ctx_new(SslMethod* m) @cname("SSL_CTX_new");
extern fn void ssl_ctx_free(SslCtx* ctx) @cname("SSL_CTX_free");
extern fn CLong ssl_ctx_ctrl(SslCtx* ctx, CInt cmd, CLong larg, void* parg) @cname("SSL_CTX_ctrl");
extern fn ulong ssl_ctx_set_options(SslCtx* ctx, ulong op) @cname("SSL_CTX_set_options");
extern fn ulong ssl_ctx_get_options(SslCtx* ctx) @cname("SSL_CTX_get_options");
extern fn CInt ssl_ctx_get_verify_depth(SslCtx* ctx) @cname("SSL_CTX_get_verify_depth");
extern fn void ssl_ctx_set_verify(SslCtx* ctx, CInt mode, void* cb) @cname("SSL_CTX_set_verify");
extern fn CInt ssl_ctx_get_verify_mode(SslCtx* ctx) @cname("SSL_CTX_get_verify_mode");
extern fn void ssl_ctx_set_verify_depth(SslCtx* ctx, CInt depth) @cname("SSL_CTX_set_verify_depth");
extern fn CInt ssl_ctx_set_default_verify_paths(SslCtx* ctx) @cname("SSL_CTX_set_default_verify_paths");
extern fn CInt ssl_ctx_load_verify_file(SslCtx* ctx, CStr file) @cname("SSL_CTX_load_verify_file");
extern fn CInt ssl_ctx_load_verify_dir(SslCtx* ctx, CStr dir) @cname("SSL_CTX_load_verify_dir");
extern fn CInt ssl_ctx_load_verify_store(SslCtx* ctx, CStr uri) @cname("SSL_CTX_load_verify_store");
extern fn CInt ssl_ctx_use_certificate_chain_file(SslCtx* ctx, CStr file) @cname("SSL_CTX_use_certificate_chain_file");
extern fn CInt ssl_ctx_use_privatekey_file(SslCtx* ctx, CStr file, CInt type) @cname("SSL_CTX_use_PrivateKey_file");
extern fn CInt ssl_ctx_check_private_key(SslCtx* ctx) @cname("SSL_CTX_check_private_key");
// Non-NULL userdata is used by the default passphrase callback as the passphrase: an encrypted key then fails
// instead of prompting on the terminal userdata must stay valid for the call: pass a static "" string.
extern fn void ssl_ctx_set_default_passwd_cb_userdata(SslCtx* ctx, void* userdata) @cname("SSL_CTX_set_default_passwd_cb_userdata");
extern fn void* ssl_ctx_get_default_passwd_cb_userdata(SslCtx* ctx) @cname("SSL_CTX_get_default_passwd_cb_userdata");
extern fn void ssl_ctx_set_client_ca_list(SslCtx* ctx, void* list) @cname("SSL_CTX_set_client_CA_list");
extern fn void* ssl_load_client_ca_file(CStr file) @cname("SSL_load_client_CA_file");
extern fn CInt ssl_ctx_set_alpn_protos(SslCtx* ctx, char* protos, CUInt len) @cname("SSL_CTX_set_alpn_protos"); // 0 = success (inverted!)
extern fn CInt ssl_ctx_set_cipher_list(SslCtx* ctx, CStr list) @cname("SSL_CTX_set_cipher_list");
extern fn CInt ssl_ctx_set_ciphersuites(SslCtx* ctx, CStr list) @cname("SSL_CTX_set_ciphersuites");
extern fn CInt ssl_ctx_set_session_id_context(SslCtx* ctx, char* ctx_id, CUInt len) @cname("SSL_CTX_set_session_id_context");

extern fn Ssl* ssl_new(SslCtx* ctx) @cname("SSL_new");
extern fn void ssl_free(Ssl* s) @cname("SSL_free");
extern fn void ssl_set_bio(Ssl* s, Bio* rbio, Bio* wbio) @cname("SSL_set_bio"); // takes ownership of both
extern fn void ssl_set_connect_state(Ssl* s) @cname("SSL_set_connect_state");
extern fn void ssl_set_accept_state(Ssl* s) @cname("SSL_set_accept_state");
extern fn CInt ssl_do_handshake(Ssl* s) @cname("SSL_do_handshake");
extern fn CInt ssl_is_init_finished(Ssl* s) @cname("SSL_is_init_finished");
extern fn CInt ssl_read_ex(Ssl* s, void* buf, usz num, usz* readbytes) @cname("SSL_read_ex");
extern fn CInt ssl_write_ex(Ssl* s, void* buf, usz num, usz* written) @cname("SSL_write_ex");
extern fn CInt ssl_shutdown(Ssl* s) @cname("SSL_shutdown");
extern fn CInt ssl_get_shutdown(Ssl* s) @cname("SSL_get_shutdown");
extern fn CInt ssl_get_error(Ssl* s, CInt ret) @cname("SSL_get_error");
extern fn CLong ssl_ctrl(Ssl* s, CInt cmd, CLong larg, void* parg) @cname("SSL_ctrl");
extern fn CInt ssl_set1_host(Ssl* s, CStr hostname) @cname("SSL_set1_host");
extern fn void ssl_set_hostflags(Ssl* s, CUInt flags) @cname("SSL_set_hostflags");
extern fn X509VerifyParam* ssl_get0_param(Ssl* s) @cname("SSL_get0_param");
extern fn CInt x509_verify_param_set1_ip_asc(X509VerifyParam* p, CStr ipasc) @cname("X509_VERIFY_PARAM_set1_ip_asc");
extern fn CUInt x509_verify_param_get_hostflags(X509VerifyParam* p) @cname("X509_VERIFY_PARAM_get_hostflags");
extern fn CStr x509_verify_param_get1_ip_asc(X509VerifyParam* p) @cname("X509_VERIFY_PARAM_get1_ip_asc"); // owned: crypto_free
extern fn void crypto_free(void* p, CStr file, CInt line) @cname("CRYPTO_free");
extern fn CLong ssl_get_verify_result(Ssl* s) @cname("SSL_get_verify_result");
extern fn CStr x509_verify_cert_error_string(CLong n) @cname("X509_verify_cert_error_string");
extern fn CStr ssl_get_version(Ssl* s) @cname("SSL_get_version");
extern fn CInt ssl_version(Ssl* s) @cname("SSL_version");
extern fn SslCipher* ssl_get_current_cipher(Ssl* s) @cname("SSL_get_current_cipher");
extern fn CStr ssl_cipher_get_name(SslCipher* c) @cname("SSL_CIPHER_get_name");
extern fn void ssl_get0_alpn_selected(Ssl* s, char** data, CUInt* len) @cname("SSL_get0_alpn_selected");
extern fn CInt ssl_session_reused(Ssl* s) @cname("SSL_session_reused");
extern fn SslSession* ssl_get1_session(Ssl* s) @cname("SSL_get1_session");
extern fn CInt ssl_set_session(Ssl* s, SslSession* sess) @cname("SSL_set_session");
extern fn void ssl_session_free(SslSession* sess) @cname("SSL_SESSION_free");
extern fn CInt i2d_ssl_session(SslSession* s, char** pp) @cname("i2d_SSL_SESSION");
extern fn SslSession* d2i_ssl_session(SslSession** a, char** pp, CLong length) @cname("d2i_SSL_SESSION");
extern fn X509Cert* ssl_get1_peer_certificate(Ssl* s) @cname("SSL_get1_peer_certificate"); // owned: x509_free
extern fn void x509_free(X509Cert* x) @cname("X509_free");
extern fn CInt i2d_x509(X509Cert* x, char** pp) @cname("i2d_X509");
extern fn EvpMd* evp_sha256() @cname("EVP_sha256");
extern fn CInt x509_digest(X509Cert* x, EvpMd* md, char* buf, CUInt* len) @cname("X509_digest");
extern fn CInt crypto_memcmp(void* a, void* b, usz len) @cname("CRYPTO_memcmp"); // 0 = equal, constant time
extern fn void openssl_cleanse(void* p, usz len) @cname("OPENSSL_cleanse");

extern fn BioMethod* bio_s_mem() @cname("BIO_s_mem");
extern fn Bio* bio_new(BioMethod* m) @cname("BIO_new");
extern fn CInt bio_free(Bio* b) @cname("BIO_free");
extern fn CInt bio_read(Bio* b, void* data, CInt len) @cname("BIO_read");
extern fn CInt bio_write(Bio* b, void* data, CInt len) @cname("BIO_write");
extern fn usz bio_ctrl_pending(Bio* b) @cname("BIO_ctrl_pending");
extern fn CInt bio_test_flags(Bio* b, CInt flags) @cname("BIO_test_flags");

extern fn ulong err_get_error() @cname("ERR_get_error");
extern fn ulong err_peek_error() @cname("ERR_peek_error");
extern fn void err_clear_error() @cname("ERR_clear_error");
extern fn void err_error_string_n(ulong e, char* buf, usz len) @cname("ERR_error_string_n");
extern fn CStr err_reason_error_string(ulong e) @cname("ERR_reason_error_string");

// ---- helpers implemented in C3 (macros in the headers) ----
// Return 1 on success like the C macros.
fn CLong ctx_set_min_proto(SslCtx* ctx, CInt v) => ssl_ctx_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, v, null);
fn CLong ctx_set_max_proto(SslCtx* ctx, CInt v) => ssl_ctx_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, v, null);
fn CLong ctx_get_min_proto(SslCtx* ctx) => ssl_ctx_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, null);
fn CLong ctx_get_max_proto(SslCtx* ctx) => ssl_ctx_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, null);
fn CLong ctx_set_groups(SslCtx* ctx, CStr list) => ssl_ctx_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, list);
fn CLong set_sni(Ssl* s, CStr name) => ssl_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME, name);

// OpenSSL 3 error-code layout (macros in err.h): system errors have bit 31 set, then reason = errno.
fn bool err_is_system(ulong e) => (e >> 31) & 1 != 0;
fn CInt err_errno(ulong e) => (CInt)(e & 0x7FFFFFFF);
fn CInt err_lib(ulong e) => (CInt)((e >> 23) & 0xFF);
fn CInt err_reason(ulong e) => (CInt)(e & 0x7FFFFF);

fn void? init()
{
	if (openssl_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, null) == 0) return tls::LIBRARY_INIT_FAILED~;
	if (openssl_version_num() < 0x30000000) return tls::LIBRARY_INIT_FAILED~;
}

fn ulong err_take(char[] buf)
{
	ulong e = err_peek_error();
	if (e != 0 && buf.len > 0)
	{
		err_error_string_n(e, buf.ptr, buf.len);
	}
	else if (buf.len > 0)
	{
		buf[0] = 0;
	}
	err_clear_error();
	return e;
}
