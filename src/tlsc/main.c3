// tlsc: a small TLS tool. As a client it connects, reports what was negotiated, and relays stdin and stdout.
// As a server (--listen) it runs an echo server.
module tlsc;

import tls;
import std::io, std::net::tcp, std::time, std::thread, std::encoding::hex;

const String VERSION = env::PROJECT_VERSION;

const String USAGE = `tlsc: connect to a TLS server, or run an echo server

usage:
  tlsc [options] HOST PORT
  tlsc --listen PORT --cert FILE --key FILE [--client-ca FILE] [--alpn a,b] [--tls12] [--verbose]

client options:
  --ca FILE            trust only the CAs in this PEM file (default: the system store)
  --ca-dir DIR         trust the CAs in this OpenSSL hashed directory
  --cert FILE --key FILE   client certificate and key (PEM) for mutual TLS
  --name NAME          verify the certificate for NAME instead of HOST
  --alpn a,b           offer these protocols
  --groups LIST        key exchange groups, e.g. X25519:P-256
  --pin-sha256 HEX     the server certificate must have this SHA-256 (as well as verifying)
  --pinned-only        trust the pin alone (no CA, no name): for self-signed devices; needs --pin-sha256
  --insecure           do NOT verify the server certificate
  --chain-only         verify the chain but not the host name; needs --insecure
  --tls12              do not use TLS 1.3
  --timeout SECONDS    wait this long for the network (default 10)
  --verbose            say more
  --version, --help
Standard input is sent to the server and the answer is written to standard output.`;

struct Options
{
	bool listen;
	int port;
	String host;
	String cert;
	String key;
	String ca;
	String ca_dir;
	String client_ca;
	String name;
	String alpn;
	String groups;
	String pin;
	bool pinned_only;
	bool insecure;
	bool chain_only;
	bool tls12;
	bool verbose;
	int timeout_s;
	bool help;
	bool show_version;
}

// 0 = ok; 2 = usage error (already reported).
fn int parse(String[] args, Options* o)
{
	String[2] positional;
	usz npos = 0;
	for (usz i = 1; i < args.len; i++)
	{
		String a = args[i];
		bool has_value = i + 1 < args.len;
		switch (a)
		{
			case "--help":
				o.help = true;
			case "--version":
				o.show_version = true;
			case "--listen":
				if (!has_value) return usage_error(a);
				o.listen = true;
				o.port = (int)string::to_integer{int}(args[++i]) ?? -1;
			case "--cert":
				if (!has_value) return usage_error(a);
				o.cert = args[++i];
			case "--key":
				if (!has_value) return usage_error(a);
				o.key = args[++i];
			case "--ca":
				if (!has_value) return usage_error(a);
				o.ca = args[++i];
			case "--ca-dir":
				if (!has_value) return usage_error(a);
				o.ca_dir = args[++i];
			case "--client-ca":
				if (!has_value) return usage_error(a);
				o.client_ca = args[++i];
			case "--name":
				if (!has_value) return usage_error(a);
				o.name = args[++i];
			case "--alpn":
				if (!has_value) return usage_error(a);
				o.alpn = args[++i];
			case "--groups":
				if (!has_value) return usage_error(a);
				o.groups = args[++i];
			case "--pin-sha256":
				if (!has_value) return usage_error(a);
				o.pin = args[++i];
			case "--timeout":
				if (!has_value) return usage_error(a);
				o.timeout_s = (int)string::to_integer{int}(args[++i]) ?? -1;
			case "--pinned-only":
				o.pinned_only = true;
			case "--insecure":
				o.insecure = true;
			case "--chain-only":
				o.chain_only = true;
			case "--tls12":
				o.tls12 = true;
			case "--verbose":
				o.verbose = true;
			default:
				if (a.starts_with("--") || npos >= positional.len) return usage_error(a);
				positional[npos++] = a;
		}
	}
	if (o.help || o.show_version) return 0;
	if (o.listen)
	{
		if (o.port < 0 || o.cert.len == 0 || o.key.len == 0 || npos != 0) return usage_error("--listen");
		return 0;
	}
	if (npos != 2) return usage_error("HOST PORT");
	o.host = positional[0];
	o.port = (int)string::to_integer{int}(positional[1]) ?? -1;
	if (o.port < 0 || o.port > 65535) return usage_error("PORT");
	if (o.timeout_s < 0) o.timeout_s = -1;
	// the ways to weaken verification have to be asked for by name
	if (o.chain_only && !o.insecure)
	{
		io::eprintn("--chain-only turns the host name check off: it needs --insecure as well");
		return 2;
	}
	if (o.pinned_only && o.pin.len == 0)
	{
		io::eprintn("--pinned-only needs --pin-sha256");
		return 2;
	}
	if (o.pinned_only && o.insecure)
	{
		io::eprintn("--pinned-only and --insecure exclude each other");
		return 2;
	}
	return 0;
}

fn int usage_error(String what)
{
	io::eprintfn("tlsc: bad or missing argument: %s (see --help)", what);
	return 2;
}

fn String describe(fault f) => f.description;

// A copy of text from the network that is safe to print: anything but visible ASCII becomes '?'.
fn String safe(String s)
{
	DString d = dstring::temp();
	foreach (c : s) d.append_char(c >= 0x20 && c < 0x7f ? c : '?');
	return d.str_view();
}

// ---- client ----

fn int client(Options* o)
{
	tls::ClientConfig cfg = {
		.ca_file = o.ca,
		.ca_dir = o.ca_dir,
		.client_cert_file = o.cert,
		.client_key_file = o.key,
		.groups = o.groups,
	};
	String[16] names;
	usz count = 0;
	if (o.alpn.len > 0)
	{
		foreach (part : o.alpn.tsplit(","))
		{
			if (count < names.len) names[count++] = part;
		}
		cfg.alpn = names[:count];
	}
	if (o.tls12) cfg.max_version = TLS_1_2;
	if (o.pin.len > 0)
	{
		char[]? pin = hex::tdecode(o.pin);
		if (catch err = pin)
		{
			io::eprintn("--pin-sha256 must be 64 hexadecimal digits");
			return 2;
		}
		cfg.pin_sha256 = pin;
	}
	if (o.pinned_only) cfg.verify = PINNED_ONLY;
	if (o.insecure) cfg.verify = o.chain_only ? CHAIN_ONLY : INSECURE_NONE;
	Duration timeout = (o.timeout_s > 0 ? o.timeout_s : 10) * time::SEC;

	tls::Context? ctx = tls::new_client_context(&cfg);
	if (catch err = ctx)
	{
		io::eprintfn("error: %s", describe(err));
		return 1;
	}
	defer ctx.free();
	tls::TcpTransport? tcp = tls::tcp_connect(o.host, o.port, timeout);
	if (catch err = tcp)
	{
		io::eprintfn("error: cannot connect to %s:%d: %s", o.host, o.port, describe(err));
		return 1;
	}
	defer (void)tcp.close();
	tls::TlsTransport*? t = tls::connect(&ctx, &tcp, o.name.len > 0 ? o.name : o.host, timeout);
	if (catch err = t)
	{
		io::eprintfn("error: %s", describe(err));
		return 1;
	}
	defer t.free();
	io::printfn("%s %s", t.conn.version_name(), t.conn.cipher_name());
	if (t.conn.alpn_selected().len > 0) io::printfn("alpn: %s", safe(t.conn.alpn_selected()));
	switch (cfg.verify)
	{
		case FULL:
			io::printn("verify: ok");
		case CHAIN_ONLY:
			io::printn("verify: ok (host name not checked)");
		case PINNED_ONLY:
			io::printn("verify: pinned");
		case INSECURE_NONE:
			io::printn("verify: SKIPPED");
	}
	(void)io::stdout().flush();
	relay(t, timeout);
	(void)t.close();
	return 0;
}

// Standard input to the server, the server's answer to standard output, until input ends and the answer has stopped.
fn void relay(tls::TlsTransport* t, Duration timeout)
{
	char[4096] buf;
	while (true)
	{
		sz? n = io::stdin().read(&buf);
		if (catch err = n) break;
		if (@catch(t.write(buf[:n], timeout))) return;
		if (!answer(t, 300 * time::MS)) return;
	}
	// input is over: collect what is still coming
	while (answer(t, 1 * time::SEC)) {}
}

// Writes what the server sent within `wait`. False when nothing came or the connection ended.
fn bool answer(tls::TlsTransport* t, Duration wait)
{
	char[4096] buf;
	bool got = false;
	while (true)
	{
		usz? n = t.read(&buf, got ? 50 * time::MS : wait);
		if (catch err = n) return got && err == tls::TIMEOUT;
		(void)io::stdout().write(buf[:n]);
		(void)io::stdout().flush();
		got = true;
	}
}

// ---- server ----

fn void serve(tls::Context* ctx, TcpSocket sock, bool verbose)
{
	tls::TcpTransport tcp = tls::tcp_wrap(sock);
	defer (void)tcp.close();
	tls::TlsTransport*? t = tls::accept(ctx, &tcp, 10 * time::SEC);
	if (catch err = t)
	{
		if (verbose) io::eprintfn("handshake failed: %s", describe(err));
		return;
	}
	defer t.free();
	if (verbose)
	{
		String name = t.conn.requested_name();
		io::eprintfn("accepted: %s sni=%s alpn=%s", t.conn.version_name(), name.len > 0 ? name : "-", t.conn.alpn_selected().len > 0 ? t.conn.alpn_selected() : "-");
		char[]? fp = t.conn.peer_cert_sha256();
		if (try f = fp)
		{
			io::eprintfn("client certificate sha256=%s", hex::tencode(f));
			free(f);
		}
	}
	char[4096] buf;
	while (true)
	{
		usz? n = t.read(&buf, 60 * time::SEC);
		if (catch err = n)
		{
			if (verbose) io::eprintfn("closed: %s", describe(err));
			break;
		}
		if (catch err = t.write(buf[:n], 10 * time::SEC))
		{
			if (verbose) io::eprintfn("write failed: %s", describe(err));
			break;
		}
	}
	(void)t.close();
}

fn int listen(Options* o)
{
	tls::ServerConfig cfg = { .cert_file = o.cert, .key_file = o.key, .client_ca_file = o.client_ca };
	if (o.tls12) cfg.max_version = TLS_1_2;
	String[16] names;
	usz count = 0;
	if (o.alpn.len > 0)
	{
		foreach (part : o.alpn.tsplit(","))
		{
			if (count < names.len) names[count++] = part;
		}
		cfg.alpn = names[:count];
	}
	tls::Context? ctx = tls::new_server_context(&cfg);
	if (catch err = ctx)
	{
		io::eprintfn("cannot set up the server: %s", describe(err));
		return 1;
	}
	defer ctx.free();
	TcpServerSocket? server = tcp::listen("127.0.0.1", o.port, 8, REUSEADDR);
	if (catch err = server)
	{
		io::eprintfn("cannot listen on port %d: %s", o.port, describe(err));
		return 1;
	}
	defer (void)server.close();
	io::printfn("listening on %d", server.local_port()!!);
	(void)io::stdout().flush();
	while (true)
	{
		TcpSocket? sock = tcp::accept(&server);
		if (catch err = sock)
		{
			// persistent failures (no descriptors left) must not turn this into a busy loop
			(void)thread::sleep_ms(100);
			continue;
		}
		serve(&ctx, sock, o.verbose);
	}
}

fn int main(String[] args)
{
	Options o = { .port = -1 };
	int rc = parse(args, &o);
	if (rc != 0)
	{
		io::eprintn(USAGE);
		return rc;
	}
	if (o.help)
	{
		io::printn(USAGE);
		return 0;
	}
	if (o.show_version)
	{
		io::printfn("tlsc %s", VERSION);
		return 0;
	}
	return o.listen ? listen(&o) : client(&o);
}
