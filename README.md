## TLS for C3

TLS 1.2 and 1.3 for the [C3 programming language](http://c3-lang.org), client and server, backed by the system
OpenSSL 3 through a small binding that lives in one file (`ossl.c3`).

* Certificate chain and host name are verified by default (SAN rules of RFC 9525), SNI, ALPN, client certificates
  (mutual TLS), certificate pinning, session resumption, a clean `close_notify`/truncation distinction.
* The engine is sans-IO (bytes in, bytes out, no sockets, no clock); `TlsTransport` runs it over any `Transport`
  (a blocking byte stream with a timeout on every call), and `TcpTransport` is one.
* Tested against `openssl s_server` and `openssl s_client` and a set of misbehaving Python peers, not only against itself.
* No headers are needed: the OpenSSL functions are declared in C3 (`ossl.c3`).

Status: 0.1.0, work in progress. Linux is built and tested; macOS and Windows are type-checked and have CI jobs that
have not run yet.

Requires [c3c](https://github.com/c3lang/c3c) v0.8.6.

### Client

`tls::connect` runs the handshake over a `Transport` and returns a `TlsTransport`, which is itself a `Transport`.
If the handshake fails nothing is closed, so the transport underneath is still yours; after a successful one the
`TlsTransport` owns it.

```
ClientConfig cfg = { .ca_file = "ca.pem", .alpn = { "mqtt" } };
Context ctx = tls::new_client_context(&cfg)!;
defer ctx.free();
TcpTransport tcp = tls::tcp_connect("broker.example", 8883, 5 * time::SEC)!;
TlsTransport* t = tls::connect(&ctx, &tcp, "broker.example", 5 * time::SEC)!;
defer t.free();
t.write("hello", 5 * time::SEC)!;
char[512] buf;
usz n = t.read(&buf, 5 * time::SEC)!;
t.close()!;
```

The `Context` is made once and shared; it must outlive the connections made from it. The timeout of `connect` covers
the whole handshake; the timeout of `read` and `write` covers the whole call.

#### A private broker CA with mutual TLS

```
ClientConfig cfg = {
	.ca_file = "broker-ca.pem",
	.client_cert_file = "gateway.pem",
	.client_key_file = "gateway.key",
	.alpn = { "mqtt" },
};
Context ctx = tls::new_client_context(&cfg)!;
defer ctx.free();
TcpTransport tcp = tls::tcp_connect("broker.plant.example", 8883, 5 * time::SEC)!;
TlsTransport* t = tls::connect(&ctx, &tcp, "broker.plant.example", 5 * time::SEC)!;
defer t.free();
io::printfn("%s, ALPN %s", t.conn.version_name(), t.conn.alpn_selected());
```

The private key must not be encrypted (an encrypted key is `KEY_LOAD_FAILED`; there is never a passphrase prompt).
With a TLS 1.3 broker a refused client certificate shows up on the first `read`, as a `ALERT_RECEIVED` fault.
For a device with a self-signed certificate use `verify = PINNED_ONLY` and `pin_sha256` (the SHA-256 of the
certificate's DER form) instead of a CA.

### Server

`tls::accept(&ctx, &tcp, timeout)` is the counterpart of `connect` for an accepted connection. The server `Context`
comes from `tls::new_server_context` (certificate chain, key, optionally `client_ca_file` to demand a client
certificate, and `alpn` to offer protocols). `Conn.requested_name()` is the name the client sent.

```
ServerConfig cfg = { .cert_file = "server.pem", .key_file = "server.key", .client_ca_file = "clients-ca.pem" };
Context ctx = tls::new_server_context(&cfg)!;
defer ctx.free();
TcpServerSocket listener = tcp::listen("0.0.0.0", 8883, 8)!;
defer (void)listener.close();
TcpTransport tcp = tls::tcp_wrap(tcp::accept(&listener)!);
TlsTransport* t = tls::accept(&ctx, &tcp, 10 * time::SEC)!;
defer t.free();
```

### The Transport contract

`Transport` is a small blocking byte-stream interface with a timeout on every call (a timeout of `DURATION_ZERO`
waits forever):

* `read(buf, timeout)` returns 1 to `buf.len` bytes; an empty buffer returns 0 at once.
* `write(data, timeout)` sends all of `data` or fails.
* `close()` can be called again without harm.
* `TIMEOUT` and `CLOSED` are the faults a caller has to know. `CLOSED` also means "the peer sent close_notify"; the
  end of the stream *without* close_notify is `TRUNCATED` (a possible truncation attack: decide what it means for your
  protocol).

A fault from `write` on a `TlsTransport` is final: part of the data may have been sent, and TLS cannot continue
after a gap, so every later call reports the same fault and the connection has to be made again. A `read` that times
out can simply be called again.

`TcpTransport` implements it over a TCP socket (a poll based timeout). `MemTransport` is an in-memory pair for tests.
Other libraries can declare an interface of the same shape; a `TlsTransport*` converts to it with an explicit cast,
but the faults stay `tls::TIMEOUT` and `tls::CLOSED`, so match them by name.

### Security defaults

* The certificate chain and the host name are checked. A host name is matched against the certificate's subject
  alternative names only (a common name alone is not enough), wildcards cover one label, an IP address matches only an
  IP entry. Turning this off takes a deliberately loud setting (`VerifyMode.INSECURE_NONE`, `CHAIN_ONLY`).
* A configured `ca_file` or `ca_dir` **replaces** the system store (`also_system_roots` keeps it). Without either, the
  system store is used.
* TLS 1.2 is the floor, 1.3 the ceiling. Compression and renegotiation are off (a renegotiation request is declined
  with a `no_renegotiation` alert).
* OpenSSL's `openssl.cnf` is **not** loaded: the settings of this library do not depend on the host's configuration.
  (Distributions with a system-wide crypto policy, for example RHEL, are therefore not consulted.)
* Nothing ever prompts on the terminal.
* A session (`export_session`) is bound to the server name and to the verification settings it was made under, and a
  connection that did not check its peer cannot hand one on. The blob holds secrets: wipe it (`wipe_session`) when done.
* The library does not use the temp allocator, so connections can be made from any thread.

### Errors

Every error is a C3 fault of module `tls`; OpenSSL's detail text is kept in `Conn.error_text` for diagnostics only.

| fault | meaning |
|---|---|
| `TIMEOUT`, `CLOSED` | transport: nothing in time; end of stream or close_notify |
| `TRUNCATED` | the stream ended without close_notify |
| `CERT_EXPIRED`, `CERT_NOT_YET_VALID` | validity period |
| `CERT_UNTRUSTED`, `CERT_SELF_SIGNED` | issuer unknown, self-signed |
| `CERT_INVALID`, `CERT_REVOKED` | other certificate problems (purpose, CA flag, weak key), revoked |
| `HOSTNAME_MISMATCH` | the name is not in the certificate |
| `PIN_MISMATCH` | the certificate is not the pinned one |
| `ALERT_RECEIVED` | the peer sent a fatal alert (`Conn.last_alert` has its code) |
| `PROTOCOL_ERROR`, `PROTOCOL_VERSION`, `NO_SHARED_CIPHER` | malformed input, version or cipher mismatch |
| `ALPN_MISMATCH`, `NO_PEER_CERT` | required ALPN not selected; server side: no client certificate |
| `CONFIG_INVALID`, `CA_LOAD_FAILED`, `CERT_LOAD_FAILED`, `KEY_LOAD_FAILED` | configuration and files |
| `SESSION_INVALID`, `NOT_CONNECTED` | session problems, use before the handshake |

### Installing OpenSSL

OpenSSL 3.0 or later is needed at run time (3.2 or later for the Windows system store).

* **Linux**: the distribution package (`libssl3` on Debian and Ubuntu); the manifest links `libssl.so.3`.
* **macOS**: `brew install openssl@3` (never the system LibreSSL); the manifest links the Homebrew location
  (`/opt/homebrew/opt/openssl@3` or `/usr/local/opt/openssl@3`).
* **Windows**: the DLLs of a 3.x build (`libssl-3-x64.dll`, `libcrypto-3-x64.dll`) next to your executable, and the
  import libraries (`libssl.lib`, `libcrypto.lib`) at link time. Keep the DLLs in the application directory and do not
  rely on `PATH`: the application directory is searched first. The system store is read through OpenSSL's
  `org.openssl.winstore://` URI, which needs OpenSSL 3.2 or later; with an older one pass `ca_file`.

macOS and Windows are type-checked only so far.

### The `tlsc` tool

`c3c build tlsc` builds a small tool, a client in the spirit of `openssl s_client` and an echo server:

```
build/tlsc --ca ca.pem broker.example 8883 < request.txt
build/tlsc --pinned-only --pin-sha256 HEX device.local 4840 < /dev/null
build/tlsc --listen 8443 --cert server.pem --key server.key [--client-ca ca.pem] [--alpn h2,http/1.1]
```

It prints the negotiated version and cipher and a `verify:` line (`ok`, `pinned`, or `SKIPPED` with `--insecure`), then
relays standard input and output. Verification can only be turned off by name (`--insecure`, `--chain-only`).

### Tests

`c3c test` runs the unit tests. Tests that need certificates or real peers print `SKIP` and pass without them. For the
full run:

```
bash tests/pki/make-pki.sh                       # test certificates (openssl command line), once
python3 -I tests/peer/run.py run -- c3c test     # starts the peers, runs the tests, stops the peers
python3 -I tests/peer/run.py serve-test          # our server against openssl s_client (after c3c build tlsc)
```

Set `TLS_REQUIRE_PKI=1` and `TLS_REQUIRE_PEERS=1` to make a missing prerequisite fail instead of skip (CI does).
`tests/check-symbols.sh ossl.c3` checks that every OpenSSL symbol the binding names exists in the installed libraries.

### License

MIT, see `LICENSE`.
