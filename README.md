## TLS for C3

TLS 1.2/1.3 client (server mode later) for the [C3 programming
language](http://c3-lang.org), backed by the system OpenSSL 3 through a small,
isolated binding. The engine is sans-IO: it turns bytes into events and events
into bytes, with a blocking adapter on top.

Status: work in progress (0.1.0). So far: the wire codecs (TLS record header,
alerts, ALPN lists, ClientHello parser) and the `Transport` layer below.

### Transport

`Transport` is a small blocking byte-stream interface with a timeout on every
call. `TIMEOUT` and `CLOSED` are the only faults a caller has to know; a read
returns 1..n bytes, a write sends everything or fails, `close` is idempotent.
`TcpTransport` implements it over a TCP socket (poll based timeout, a timeout
of `DURATION_ZERO` waits forever); `MemTransport` is an in-memory pair for
tests.

```
TcpTransport t = tls::tcp_connect("example.org", 80, 5 * time::SEC)!;
defer (void)t.close();
t.write("GET / HTTP/1.0\r\n\r\n", 5 * time::SEC)!;
char[512] buf;
usz n = t.read(&buf, 5 * time::SEC)!;
```

Requires [c3c](https://github.com/c3lang/c3c) v0.8.6.

### License

MIT, see `LICENSE`.
