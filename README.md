## TLS for C3

TLS 1.2/1.3 client (server mode later) for the [C3 programming
language](http://c3-lang.org), backed by the system OpenSSL 3 through a small,
isolated binding. The engine is sans-IO: it turns bytes into events and events
into bytes, with a blocking adapter on top.

Status: work in progress (0.1.0). Only the wire codecs (TLS record header,
alerts, ALPN encoding) exist so far.

Requires [c3c](https://github.com/c3lang/c3c) v0.8.6.

### License

MIT, see `LICENSE`.
