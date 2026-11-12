// TLS 1.2 and 1.3 for C3 on OpenSSL 3. The public API is spread over the files of module `tls`:
// config.c3 (settings), engine.c3 (sans-IO Context and Conn), adapter.c3 (TlsTransport), transport.c3 and tcp.c3
// (the Transport interface and TCP), error.c3 (faults), wire.c3 (TLS record and hello parsing, module tls::wire).
module tls;

// The version of this library. Kept equal to "version" in project.json by tools/bump_version.c3 and by a test.
const String VERSION = "0.1.0";
