// OpenSSL-specific engine on memory BIOs. A pure-C3 backend provides the same Context/Conn API in its own file.
module tls;
import tls::ossl;
import tls::wire;
import std::io, std::hash::sha256;

// Used as the passphrase of every private key: a non-NULL value stops OpenSSL's default callback from asking on the
// terminal, so an encrypted key fails to load instead of blocking.
const char[1] NO_PASSPHRASE = { 0 };
const String SESSION_ID_CONTEXT = "tls.c3l";

// Connections keep a pointer to their Context (for the pin and the verification mode): the Context value must stay
// where it is, and must not be freed, until every connection made from it has been freed.
struct Context
{
	ossl::SslCtx* handle;
	bool server;
	bool requires_client_cert;   // server context: a client certificate from the configured CAs is demanded
	VerifyMode verify;           // client context
	char[] pin_sha256;           // copy of the configured pin (owned), empty = none
	bool require_alpn;
	bool has_alpn;
	bool session_cache;
	bool system_roots_loaded;    // whether the system trust store was added
	Allocator allocator;
}

// Clears the OpenSSL error queue and returns the fault, so one failed call never poisons the next one.
fn fault ossl_fail(fault f)
{
	ossl::err_clear_error();
	return f;
}

// SSL_CTX is created once and shared by many connections; free it after all of them.
fn Context? new_client_context(ClientConfig* cfg, Allocator allocator = mem)
{
	cfg.validate()!;
	ossl::init()!;
	defer ossl::err_clear_error();

	ossl::SslCtx* ctx = ossl::ssl_ctx_new(ossl::tls_client_method());
	if (!ctx) return ossl_fail(OPENSSL_ERROR)~;
	defer catch ossl::ssl_ctx_free(ctx);

	if (ossl::ctx_set_min_proto(ctx, cfg.min_wire()) != 1) return ossl_fail(OPENSSL_ERROR)~;
	if (ossl::ctx_set_max_proto(ctx, cfg.max_wire()) != 1) return ossl_fail(OPENSSL_ERROR)~;
	ossl::ssl_ctx_set_options(ctx, ossl::SSL_OP_NO_COMPRESSION | ossl::SSL_OP_NO_RENEGOTIATION);

	bool verifies_chain = cfg.verify == FULL || cfg.verify == CHAIN_ONLY;
	ossl::ssl_ctx_set_verify(ctx, verifies_chain ? ossl::SSL_VERIFY_PEER : ossl::SSL_VERIFY_NONE, null);
	ossl::ssl_ctx_set_verify_depth(ctx, cfg.max_chain_depth > 0 ? cfg.max_chain_depth : DEFAULT_CHAIN_DEPTH);

	// A configured CA must load, whatever the mode: an unusable path is an error, never an empty store.
	if (cfg.ca_file.len > 0 && ossl::ssl_ctx_load_verify_file(ctx, (char*)cfg.ca_file.zstr_tcopy()) != 1)
	{
		return ossl_fail(CA_LOAD_FAILED)~;
	}
	if (cfg.ca_dir.len > 0)
	{
		// the directory is read lazily by OpenSSL, so a missing one would only show up as an empty store later
		if (!file::is_dir(cfg.ca_dir)) return ossl_fail(CA_LOAD_FAILED)~;
		if (ossl::ssl_ctx_load_verify_dir(ctx, (char*)cfg.ca_dir.zstr_tcopy()) != 1) return ossl_fail(CA_LOAD_FAILED)~;
	}
	// Trust: a configured CA replaces the system store unless also_system_roots asks for both.
	bool system_roots = false;
	if (verifies_chain)
	{
		bool custom = cfg.ca_file.len > 0 || cfg.ca_dir.len > 0;
		if (!custom || cfg.also_system_roots)
		{
$if env::WIN32:
			// OpenSSL has no certificate directory on Windows: use the system store through its store URI (3.2 and later)
			if (ossl::ssl_ctx_load_verify_store(ctx, "org.openssl.winstore://") != 1) return ossl_fail(CA_LOAD_FAILED)~;
$else
			if (ossl::ssl_ctx_set_default_verify_paths(ctx) != 1) return ossl_fail(CA_LOAD_FAILED)~;
$endif
			system_roots = true;
		}
	}

	// Before any key is loaded, so that an encrypted key can never prompt.
	ossl::ssl_ctx_set_default_passwd_cb_userdata(ctx, &NO_PASSPHRASE);
	if (cfg.client_cert_file.len > 0)
	{
		if (ossl::ssl_ctx_use_certificate_chain_file(ctx, (char*)cfg.client_cert_file.zstr_tcopy()) != 1)
		{
			return ossl_fail(CERT_LOAD_FAILED)~;
		}
		if (ossl::ssl_ctx_use_privatekey_file(ctx, (char*)cfg.client_key_file.zstr_tcopy(), ossl::SSL_FILETYPE_PEM) != 1)
		{
			return ossl_fail(KEY_LOAD_FAILED)~;
		}
		if (ossl::ssl_ctx_check_private_key(ctx) != 1) return ossl_fail(KEY_LOAD_FAILED)~;
	}

	char[] alpn = wire::encode_alpn(cfg.alpn, tmem)!;
	if (alpn.len > 0)
	{
		// 0 means success for this one call
		if (ossl::ssl_ctx_set_alpn_protos(ctx, alpn.ptr, (CUInt)alpn.len) != 0) return ossl_fail(OPENSSL_ERROR)~;
	}
	if (cfg.cipher_list.len > 0 && ossl::ssl_ctx_set_cipher_list(ctx, (char*)cfg.cipher_list.zstr_tcopy()) != 1)
	{
		return ossl_fail(CONFIG_INVALID)~;
	}
	if (cfg.ciphersuites.len > 0 && ossl::ssl_ctx_set_ciphersuites(ctx, (char*)cfg.ciphersuites.zstr_tcopy()) != 1)
	{
		return ossl_fail(CONFIG_INVALID)~;
	}
	if (cfg.groups.len > 0 && ossl::ctx_set_groups(ctx, (char*)cfg.groups.zstr_tcopy()) != 1)
	{
		return ossl_fail(CONFIG_INVALID)~;
	}

	Context c = {
		.handle = ctx,
		.verify = cfg.verify,
		.require_alpn = cfg.require_alpn,
		.has_alpn = alpn.len > 0,
		.session_cache = cfg.session_cache,
		.system_roots_loaded = system_roots,
		.allocator = allocator,
	};
	if (cfg.pin_sha256.len > 0)
	{
		c.pin_sha256 = alloc::alloc_array_try(allocator, char, (sz)cfg.pin_sha256.len)!;
		c.pin_sha256[..] = cfg.pin_sha256[..];
	}
	return c;
}

// Server side: certificate chain and key from PEM files. With client_ca_file set, a client certificate that chains to
// those CAs is required (mutual TLS).
fn Context? new_server_context(ServerConfig* cfg, Allocator allocator = mem)
{
	cfg.validate()!;
	ossl::init()!;
	defer ossl::err_clear_error();

	ossl::SslCtx* ctx = ossl::ssl_ctx_new(ossl::tls_server_method());
	if (!ctx) return ossl_fail(OPENSSL_ERROR)~;
	defer catch ossl::ssl_ctx_free(ctx);

	if (ossl::ctx_set_min_proto(ctx, cfg.min_wire()) != 1) return ossl_fail(OPENSSL_ERROR)~;
	if (ossl::ctx_set_max_proto(ctx, cfg.max_wire()) != 1) return ossl_fail(OPENSSL_ERROR)~;
	ossl::ssl_ctx_set_options(ctx, ossl::SSL_OP_NO_COMPRESSION | ossl::SSL_OP_NO_RENEGOTIATION);
	ossl::ssl_ctx_set_verify_depth(ctx, cfg.max_chain_depth > 0 ? cfg.max_chain_depth : DEFAULT_CHAIN_DEPTH);
	// session reuse needs an identity for this context, and client certificate checks insist on one
	if (ossl::ssl_ctx_set_session_id_context(ctx, SESSION_ID_CONTEXT.ptr, (CUInt)SESSION_ID_CONTEXT.len) != 1)
	{
		return ossl_fail(OPENSSL_ERROR)~;
	}

	ossl::ssl_ctx_set_default_passwd_cb_userdata(ctx, &NO_PASSPHRASE);
	if (ossl::ssl_ctx_use_certificate_chain_file(ctx, (char*)cfg.cert_file.zstr_tcopy()) != 1)
	{
		return ossl_fail(CERT_LOAD_FAILED)~;
	}
	if (ossl::ssl_ctx_use_privatekey_file(ctx, (char*)cfg.key_file.zstr_tcopy(), ossl::SSL_FILETYPE_PEM) != 1)
	{
		return ossl_fail(KEY_LOAD_FAILED)~;
	}
	if (ossl::ssl_ctx_check_private_key(ctx) != 1) return ossl_fail(KEY_LOAD_FAILED)~;

	if (cfg.client_ca_file.len > 0)
	{
		char* ca = (char*)cfg.client_ca_file.zstr_tcopy();
		if (ossl::ssl_ctx_load_verify_file(ctx, ca) != 1) return ossl_fail(CA_LOAD_FAILED)~;
		void* names = ossl::ssl_load_client_ca_file(ca);
		if (!names) return ossl_fail(CA_LOAD_FAILED)~;
		ossl::ssl_ctx_set_client_ca_list(ctx, names); // takes ownership of the list
		ossl::ssl_ctx_set_verify(ctx, ossl::SSL_VERIFY_PEER | ossl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
	}
	if (cfg.groups.len > 0 && ossl::ctx_set_groups(ctx, (char*)cfg.groups.zstr_tcopy()) != 1)
	{
		return ossl_fail(CONFIG_INVALID)~;
	}
	return { .handle = ctx, .server = true, .requires_client_cert = cfg.client_ca_file.len > 0, .allocator = allocator };
}

fn void Context.free(&self)
{
	if (self.handle) ossl::ssl_ctx_free(self.handle);
	if (self.pin_sha256.ptr) alloc::free(self.allocator, self.pin_sha256.ptr);
	*self = {};
}

// One TLS connection: the engine sees only bytes. Ciphertext goes in with feed and comes out with take_out;
// plaintext goes in with write and out with read. No sockets, no clock, no blocking.
struct Conn
{
	ossl::Ssl* ssl;
	ossl::Bio* rbio;             // ciphertext in
	ossl::Bio* wbio;             // ciphertext out
	Context* ctx;                // not owned
	bool server;
	bool handshake_done;
	bool eof_fed;
	bool close_notify_received;
	bool close_notify_sent;
	bool pin_checked;            // the configured pin has been compared with the peer certificate
	char[32] name_hash;          // SHA-256 of the name this connection verifies; sessions are bound to it
	bool failed;                 // sticky: every later call returns the stored fault
	fault failure;
	char last_alert;             // code of the last received fatal alert, 0 = none
	char[256] error_text;        // last OpenSSL error text (diagnostics only, never key material)
	Allocator allocator;
}

// Client connection. A DNS name is sent as SNI and, with FULL verification, checked against the certificate;
// an IP literal is checked against the certificate's IP addresses and is never sent as SNI. With FULL
// verification the name is required; other modes may pass an empty name (no SNI, no name check).
fn Conn? Context.new_client_conn(&self, String server_name, Allocator allocator = mem)
{
	if (self.server || !self.handle) return CONFIG_INVALID~;
	bool check_name = self.verify == FULL;
	if (server_name.len == 0 && check_name) return CONFIG_INVALID~;
	NamePlan plan = {};
	if (server_name.len > 0) plan = validate_server_name(server_name)!;
	defer ossl::err_clear_error();

	Conn conn = self.make_conn(allocator)!;
	defer catch conn.free();
	ossl::Ssl* ssl = conn.ssl;
	ossl::ssl_set_connect_state(ssl);

	if (server_name.len > 0)
	{
		char* zname = (char*)plan.name.zstr_tcopy();
		if (plan.kind == DNS)
		{
			if (ossl::set_sni(ssl, zname) != 1) return ossl_fail(OPENSSL_ERROR)~;
			if (check_name)
			{
				ossl::ssl_set_hostflags(ssl, ossl::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | ossl::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
				if (ossl::ssl_set1_host(ssl, zname) != 1) return ossl_fail(OPENSSL_ERROR)~;
			}
		}
		else if (check_name)
		{
			if (ossl::x509_verify_param_set1_ip_asc(ossl::ssl_get0_param(ssl), zname) != 1) return ossl_fail(CONFIG_INVALID)~;
		}
	}
	conn.name_hash = sha256::hash(server_name.len > 0 ? plan.name : "");
	return conn;
}

// Server connection on a server context.
fn Conn? Context.new_server_conn(&self, Allocator allocator = mem)
{
	if (!self.server || !self.handle) return CONFIG_INVALID~;
	defer ossl::err_clear_error();
	Conn conn = self.make_conn(allocator)!;
	ossl::ssl_set_accept_state(conn.ssl);
	conn.server = true;
	return conn;
}

// An SSL object with its two memory BIOs. The SSL owns the BIOs once they are attached.
fn Conn? Context.make_conn(&self, Allocator allocator)
{
	ossl::Bio* rbio = ossl::bio_new(ossl::bio_s_mem());
	ossl::Bio* wbio = ossl::bio_new(ossl::bio_s_mem());
	ossl::Ssl* ssl = (rbio && wbio) ? ossl::ssl_new(self.handle) : null;
	if (!ssl)
	{
		if (rbio) ossl::bio_free(rbio);
		if (wbio) ossl::bio_free(wbio);
		return ossl_fail(OPENSSL_ERROR)~;
	}
	ossl::ssl_set_bio(ssl, rbio, wbio);
	return { .ssl = ssl, .rbio = rbio, .wbio = wbio, .ctx = self, .allocator = allocator };
}

fn void Conn.free(&self)
{
	if (self.ssl) ossl::ssl_free(self.ssl); // also frees both BIOs
	*self = {};
}

// Records the first fault; the error queue text is kept for diagnostics.
fn fault Conn.fail(&self, fault f)
{
	if (!self.failed)
	{
		self.failed = true;
		self.failure = f;
		ossl::err_take(&self.error_text);
	}
	ossl::err_clear_error();
	return self.failure;
}

// Ciphertext in. Returns the bytes accepted: at most MAX_INBOUND unread bytes are buffered, so a caller that is
// offered more than fits must try the rest again after read() or handshake() consumed input.
fn usz Conn.feed(&self, char[] ciphertext)
{
	if (!self.ssl) return 0;
	usz pending = ossl::bio_ctrl_pending(self.rbio);
	usz room = pending < MAX_INBOUND ? MAX_INBOUND - pending : 0;
	usz n = min((usz)ciphertext.len, room);
	if (n == 0) return 0;
	return ossl::bio_write(self.rbio, ciphertext.ptr, (CInt)n) > 0 ? n : 0;
}

// The network reported end of stream.
fn void Conn.feed_eof(&self) => self.eof_fed = true;

fn usz Conn.out_pending(&self) => self.ssl ? ossl::bio_ctrl_pending(self.wbio) : 0;

// Ciphertext out. Drain after every other call, also after faults: fatal alerts wait here.
fn usz Conn.take_out(&self, char[] buf)
{
	usz n = min((usz)buf.len, self.out_pending());
	if (n == 0) return 0;
	CInt got = ossl::bio_read(self.wbio, buf.ptr, (CInt)n);
	return got > 0 ? (usz)got : 0;
}

// Drives the handshake. true = finished; false = more input needed (drain the out queue first).
fn bool? Conn.handshake(&self)
{
	if (self.failed) return self.failure~;
	if (self.handshake_done) return true;
	if (self.close_notify_sent) return CLOSED~; // closed before the handshake finished: do not start one
	ossl::err_clear_error();
	CInt r = ossl::ssl_do_handshake(self.ssl);
	// The pin is compared as soon as the peer's certificate is known, which can be before the handshake is over:
	// in TLS 1.2 our certificate and Finished are queued in the very call that learns the server's.
	if (self.pin_mismatch())
	{
		// the peer is not the one we pinned: nothing of what OpenSSL queued may reach it
		char[512] discard;
		while (self.out_pending() > 0 && self.take_out(&discard) > 0) {}
		return self.fail(PIN_MISMATCH)~;
	}
	if (r == 1)
	{
		if (self.ctx.pin_sha256.len > 0 && !self.pin_checked) return self.fail(PIN_MISMATCH)~; // no certificate to compare
		if (self.ctx.require_alpn && self.ctx.has_alpn && self.alpn_selected().len == 0) return self.fail(ALPN_MISMATCH)~;
		self.handshake_done = true;
		return true;
	}
	CInt e = ossl::ssl_get_error(self.ssl, r);
	if (e == ossl::SSL_ERROR_WANT_READ || e == ossl::SSL_ERROR_WANT_WRITE)
	{
		if (self.eof_fed) return self.fail(TRUNCATED)~;
		return false;
	}
	return self.fail(map_ssl_error(e, self.ssl, true, &self.last_alert))~;
}

// Plaintext out. WANT_INPUT: no full record yet. CLOSED: the peer sent close_notify. TRUNCATED: the transport
// ended without it. A buffer of length 0 returns 0.
fn usz? Conn.read(&self, char[] plain)
{
	if (self.failed) return self.failure~;
	if (!self.handshake_done) return NOT_CONNECTED~;
	if (plain.len == 0) return 0;
	ossl::err_clear_error();
	usz n = 0;
	if (ossl::ssl_read_ex(self.ssl, plain.ptr, plain.len, &n) == 1) return n;
	CInt e = ossl::ssl_get_error(self.ssl, 0);
	if (e == ossl::SSL_ERROR_ZERO_RETURN)
	{
		self.close_notify_received = true;
		return CLOSED~;
	}
	if (e == ossl::SSL_ERROR_WANT_READ || e == ossl::SSL_ERROR_WANT_WRITE)
	{
		if (self.eof_fed && !self.close_notify_received) return self.fail(TRUNCATED)~;
		return WANT_INPUT~;
	}
	return self.fail(map_ssl_error(e, self.ssl, false, &self.last_alert))~;
}

// Plaintext in: all of it is encrypted into the out queue, or a fault. Empty input returns 0 and emits nothing.
fn usz? Conn.write(&self, char[] plain)
{
	if (self.failed) return self.failure~;
	if (!self.handshake_done) return NOT_CONNECTED~;
	if (self.close_notify_sent) return CLOSED~;
	if (plain.len == 0) return 0;
	ossl::err_clear_error();
	usz n = 0;
	if (ossl::ssl_write_ex(self.ssl, plain.ptr, plain.len, &n) == 1) return n;
	CInt e = ossl::ssl_get_error(self.ssl, 0);
	// a write that needs input is not a failure (only possible if the peer started something that wants a reply)
	if (e == ossl::SSL_ERROR_WANT_READ)
	{
		// the stream has ended: no input will ever arrive, so do not invite the caller to wait for it
		if (self.eof_fed && !self.close_notify_received) return self.fail(TRUNCATED)~;
		return WANT_INPUT~;
	}
	return self.fail(map_ssl_error(e, self.ssl, false, &self.last_alert))~;
}

// Queues close_notify. It does not wait for the peer's. After a fault there is nothing to send.
fn void? Conn.close_notify(&self)
{
	if (self.failed || self.close_notify_sent) return;
	self.close_notify_sent = true;
	if (!self.handshake_done) return;
	ossl::err_clear_error();
	ossl::ssl_shutdown(self.ssl);
	ossl::err_clear_error();
}

// SHA-256 of the peer certificate in DER form. False when the peer sent no certificate.
fn bool Conn.peer_digest(&self, char[32]* digest)
{
	ossl::X509Cert* cert = ossl::ssl_get1_peer_certificate(self.ssl);
	if (!cert) return false;
	defer ossl::x509_free(cert);
	CUInt len = 0;
	return ossl::x509_digest(cert, ossl::evp_sha256(), (char*)digest, &len) == 1 && len == 32;
}

// The peer certificate fingerprint, for pinning. NO_PEER_CERT when there is none.
fn char[]? Conn.peer_cert_sha256(&self, Allocator allocator = mem)
{
	char[32] digest;
	if (!self.peer_digest(&digest)) return NO_PEER_CERT~;
	char[] out = alloc::alloc_array_try(allocator, char, 32)!;
	out[..] = digest[..];
	return out;
}

// The raw X509_V_ERR_* result of the certificate check, 0 = ok.
fn long Conn.verify_result(&self) => self.ssl ? ossl::ssl_get_verify_result(self.ssl) : 0;

// "TLSv1.3", "TLSv1.2", ... once the version is known. The string belongs to OpenSSL and is static.
fn String Conn.version_name(&self)
{
	if (!self.ssl) return "";
	return ((ZString)ossl::ssl_get_version(self.ssl)).str_view();
}

// True when a pin is configured, the peer certificate is available and differs from it. The comparison happens once.
fn bool Conn.pin_mismatch(&self)
{
	if (self.ctx.pin_sha256.len == 0 || self.pin_checked) return false;
	char[32] digest;
	if (!self.peer_digest(&digest)) return false; // not received yet
	self.pin_checked = true;
	return ossl::crypto_memcmp(digest[..].ptr, self.ctx.pin_sha256.ptr, 32) != 0;
}

// The protocol the server picked through ALPN, empty when none. The bytes belong to OpenSSL and stay valid until the
// connection is freed.
fn String Conn.alpn_selected(&self)
{
	char* data = null;
	CUInt len = 0;
	ossl::ssl_get0_alpn_selected(self.ssl, &data, &len);
	if (data == null || len == 0) return "";
	return (String)data[:len];
}

// The peer certificate in DER form (a copy owned by the caller). NO_PEER_CERT when there is none.
fn char[]? Conn.peer_cert_der(&self, Allocator allocator = mem)
{
	ossl::X509Cert* cert = ossl::ssl_get1_peer_certificate(self.ssl);
	if (!cert) return NO_PEER_CERT~;
	defer ossl::x509_free(cert);
	CInt size = ossl::i2d_x509(cert, null);
	if (size <= 0) return ossl_fail(OPENSSL_ERROR)~;
	char[] der = alloc::alloc_array_try(allocator, char, (sz)size)!;
	char* at = der.ptr;
	if (ossl::i2d_x509(cert, &at) != size)
	{
		alloc::free(allocator, der.ptr);
		return ossl_fail(OPENSSL_ERROR)~;
	}
	return der;
}

// The session of this connection as a blob for a later connection to the same server: SHA-256 of the verified name
// (32 bytes) followed by the DER session. It holds the session's secrets: treat it like a key, keep it only as long as
// needed and wipe it (wipe_session) when done. A TLS 1.3 session only exists once the server's ticket has been read, so
// read from the connection before exporting; before that this is SESSION_INVALID. Needs ClientConfig.session_cache.
fn char[]? Conn.export_session(&self, Allocator allocator = mem)
{
	if (!self.ctx.session_cache || self.server) return CONFIG_INVALID~;
	if (!self.handshake_done) return NOT_CONNECTED~;
	defer ossl::err_clear_error();
	ossl::SslSession* sess = ossl::ssl_get1_session(self.ssl);
	if (!sess) return SESSION_INVALID~;
	defer ossl::ssl_session_free(sess);
	if (ossl::ssl_session_is_resumable(sess) != 1) return SESSION_INVALID~;
	CInt size = ossl::i2d_ssl_session(sess, null);
	if (size <= 0) return SESSION_INVALID~;
	char[] blob = alloc::alloc_array_try(allocator, char, (sz)(32 + size))!;
	blob[:32][..] = self.name_hash[..];
	char* at = blob.ptr + 32;
	if (ossl::i2d_ssl_session(sess, &at) != size)
	{
		wipe_session(blob);
		alloc::free(allocator, blob.ptr);
		return SESSION_INVALID~;
	}
	return blob;
}

// Offers a session from export_session to the server. Only before the handshake has started, and only for a connection
// to the same name that it was exported from. A server that no longer knows the session simply gets a full handshake:
// check session_reused() afterwards if that matters.
fn void? Conn.import_session(&self, char[] blob)
{
	if (!self.ctx.session_cache || self.server || self.handshake_done) return CONFIG_INVALID~;
	if (blob.len <= 32) return SESSION_INVALID~;
	// bound to the name: a session from another server must not silently turn into a handshake in another context
	if (ossl::crypto_memcmp(blob.ptr, &self.name_hash, 32) != 0) return SESSION_INVALID~;
	defer ossl::err_clear_error();
	char* at = blob.ptr + 32;
	ossl::SslSession* sess = ossl::d2i_ssl_session(null, &at, (CLong)(blob.len - 32));
	if (!sess) return SESSION_INVALID~;
	defer ossl::ssl_session_free(sess);
	if (ossl::ssl_set_session(self.ssl, sess) != 1) return SESSION_INVALID~;
}

// True when the handshake resumed an earlier session instead of doing a full one.
fn bool Conn.session_reused(&self) => self.ssl && ossl::ssl_session_reused(self.ssl) == 1;

// Overwrites a blob from export_session with zeros in a way the compiler cannot drop.
fn void wipe_session(char[] blob)
{
	if (blob.len > 0) ossl::openssl_cleanse(blob.ptr, blob.len);
}
