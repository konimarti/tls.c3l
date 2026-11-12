module tls;

// Every fault is public API. OpenSSL error detail goes to Conn.last_error_text(), not into the fault.
faultdef
	WANT_INPUT,          // not an error: feed more ciphertext, then retry
	NOT_CONNECTED,       // read/write before the handshake finished
	TRUNCATED,           // transport EOF without close_notify (possible truncation attack)
	HANDSHAKE_FAILED,    // generic handshake_failure / unmapped SSL_R_*
	PROTOCOL_ERROR,      // malformed or unexpected record/message
	PROTOCOL_VERSION,    // peer offers only versions below min_version (e.g. TLS 1.1 server)
	NO_SHARED_CIPHER,
	ALERT_RECEIVED,      // peer sent a fatal alert (the alert code is kept by the connection)
	CERT_EXPIRED,        // X509_V_ERR_CERT_HAS_EXPIRED
	CERT_NOT_YET_VALID,
	CERT_UNTRUSTED,      // unknown issuer / unable to get local issuer
	CERT_SELF_SIGNED,    // depth-zero self-signed or self-signed in chain
	CERT_REVOKED,
	CERT_INVALID,        // any other X509_V_ERR_* (bad CA, wrong purpose, weak key, ...)
	HOSTNAME_MISMATCH,   // X509_V_ERR_HOSTNAME_MISMATCH / IP_ADDRESS_MISMATCH
	PIN_MISMATCH,        // peer certificate SHA-256 differs from the configured pin
	NO_PEER_CERT,        // server mode: client certificate required and none sent
	ALPN_MISMATCH,       // require_alpn set and no protocol selected / server found no shared protocol
	CONFIG_INVALID,      // bad option combination, bad host name, bad ALPN, bad pin length
	CA_LOAD_FAILED,      // CA file/dir/store unreadable or invalid
	CERT_LOAD_FAILED,    // client/server cert chain file unreadable
	KEY_LOAD_FAILED,     // key unreadable, encrypted, or does not match the certificate
	SESSION_INVALID,     // imported session blob rejected or bound to another server name
	OPENSSL_ERROR,       // anything else from the error queue
	OUT_OF_MEMORY,
	LIBRARY_INIT_FAILED, // libssl missing, older than 3.0, or init failed
	TIMEOUT,             // Transport: nothing arrived / could be sent within the timeout
	CLOSED;              // Transport: peer EOF, close() called, or (Conn.read/TlsTransport.read) close_notify received
// A received close_notify is CLOSED; transport EOF without close_notify is TRUNCATED.
