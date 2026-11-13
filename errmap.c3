module tls;
import tls::ossl;

// Maps X509 verify error code (X509_V_ERR_*) to fault.
fn fault map_verify_code(long code)
{
	switch (code)
	{
		case 10:
			return CERT_EXPIRED;
		case 9:
			return CERT_NOT_YET_VALID;
		case 18:
		case 19:
			return CERT_SELF_SIGNED;
		case 2:
		case 20:
		case 21:
			return CERT_UNTRUSTED;
		case 62:
		case 64:
			return HOSTNAME_MISMATCH;
		case 23:
			return CERT_REVOKED;
		case 24: // issuer certificate has no public key
		case 26: // unsuitable purpose
		case 79: // invalid CA certificate (OpenSSL 3.5 reports a non-CA issuer with this number)
		case 9999:
		default:
			return CERT_INVALID;
	}
}

// Maps OpenSSL ERR queue reason (SSL_R_*) to fault.
fn fault map_ssl_reason(ulong err, bool handshaking, char* out_alert = null)
{
	if (err == 0) return handshaking ? HANDSHAKE_FAILED : OPENSSL_ERROR;

	// System error: call sites map specifically; fallback is OPENSSL_ERROR.
	if (ossl::err_is_system(err)) return OPENSSL_ERROR;

	CInt reason = ossl::err_reason(err);

	// Alert reasons in OpenSSL 3: 1000 + alert_code
	if (reason >= 1000 && reason <= 1255)
	{
		char alert = (char)(reason - 1000);
		if (out_alert != null) *out_alert = alert;
		if (alert == 70) // protocol_version alert
		{
			return PROTOCOL_VERSION;
		}
		return ALERT_RECEIVED;
	}

	switch (reason)
	{
		case 258: // unsupported protocol
		case 267: // wrong version number
		case 191: // no protocols available
		case 116: // bad protocol version number
			return PROTOCOL_VERSION;
		case 199: // peer did not return a certificate (server side, client certificate required)
			return NO_PEER_CERT;
		case 396: // version too low (a ClientHello below the server's minimum)
			return PROTOCOL_VERSION;
		case 244: // unexpected message
		case 156: // http request
		case 160: // length too short
		case 146: // data length too long (what newer 3.5 releases say for a record longer than allowed)
			return PROTOCOL_ERROR;
		case 193: // no shared cipher
			return NO_SHARED_CIPHER;
		case 294: // unexpected eof while reading
			return TRUNCATED;
		case 147: // decryption failed
		case 281: // decryption failed or bad record mac
		case 198: // packet length too long
			return PROTOCOL_ERROR;
		default:
			return handshaking ? HANDSHAKE_FAILED : OPENSSL_ERROR;
	}
}

// Full mapping order for a failed SSL operation: verification result first, then the error queue, then the SSL error code.
fn fault map_ssl_error(CInt ssl_err, ossl::Ssl* s, bool handshaking, char* out_alert = null)
{
	switch (ssl_err)
	{
		case ossl::SSL_ERROR_WANT_READ:
			return WANT_INPUT;
		case ossl::SSL_ERROR_ZERO_RETURN:
			return CLOSED;
		case ossl::SSL_ERROR_SSL:
			if (s != null)
			{
				CLong v = ossl::ssl_get_verify_result(s);
				if (v != 0) return map_verify_code(v);
			}
			ulong e = ossl::err_peek_error();
			if (e != 0) return map_ssl_reason(e, handshaking, out_alert);
			return handshaking ? HANDSHAKE_FAILED : OPENSSL_ERROR;
		case ossl::SSL_ERROR_SYSCALL:
			ulong e = ossl::err_peek_error();
			if (e == 0) return TRUNCATED;
			return OPENSSL_ERROR;
		default:
			return OPENSSL_ERROR;
	}
}

// Call site helpers for system/load errors.
fn fault map_ca_load_error(ulong err) => CA_LOAD_FAILED;
fn fault map_cert_load_error(ulong err) => CERT_LOAD_FAILED;
fn fault map_key_load_error(ulong err) => KEY_LOAD_FAILED;
