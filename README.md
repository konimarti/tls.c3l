## TLS for C3

TLS 1.2/1.3 client (server mode later) for the [C3 programming
language](http://c3-lang.org), backed by the system OpenSSL 3 through a small,
isolated binding. The engine is sans-IO: it turns bytes into events and events
into bytes, with a blocking adapter on top.

Status: work in progress (0.1.0). A TLS 1.2/1.3 client works over any `Transport`
(see below); server mode over sockets, sessions and the command line tool are
still to come.

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

### TLS client

`tls::connect` runs the handshake over a `Transport` and returns a
`TlsTransport`, which is itself a `Transport`. Certificates and the host name are
checked by default; a configured CA replaces the system store. If the
handshake fails nothing is closed, so the transport underneath is still yours;
after a successful one the `TlsTransport` owns it.

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

A fault from `write` on a `TlsTransport` is final: part of the data may have been sent, and TLS cannot
continue after a gap, so every later call reports the same fault and the connection has to be made again.
A `read` that times out can simply be called again.

The tests in `src/test` that talk to real peers need `tests/pki/make-pki.sh`
and `python3 -I tests/peer/run.py start` first (`stop` afterwards); without them
those tests print `SKIP` and pass.

Requires [c3c](https://github.com/c3lang/c3c) v0.8.6.

### License

MIT, see `LICENSE`.
