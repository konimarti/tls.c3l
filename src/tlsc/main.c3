// tlsc: a small TLS tool. For now it can run an echo server (--listen); the client side follows.
module tlsc;

import tls;
import std::io, std::net::tcp, std::time, std::encoding::hex;

const String USAGE = "usage: tlsc --listen PORT --cert FILE --key FILE [--client-ca FILE] [--alpn a,b] [--tls12] [--verbose]";

struct Options
{
	int port;
	String cert;
	String key;
	String client_ca;
	String alpn;
	bool tls12;
	bool verbose;
}

fn bool parse(String[] args, Options* o)
{
	for (usz i = 1; i < args.len; i++)
	{
		String a = args[i];
		bool has_value = i + 1 < args.len;
		switch (a)
		{
			case "--listen":
				if (!has_value) return false;
				o.port = (int)string::to_integer{int}(args[++i]) ?? -1;
			case "--cert":
				if (!has_value) return false;
				o.cert = args[++i];
			case "--key":
				if (!has_value) return false;
				o.key = args[++i];
			case "--client-ca":
				if (!has_value) return false;
				o.client_ca = args[++i];
			case "--alpn":
				if (!has_value) return false;
				o.alpn = args[++i];
			case "--tls12":
				o.tls12 = true;
			case "--verbose":
				o.verbose = true;
			default:
				return false;
		}
	}
	return o.port >= 0 && o.cert.len > 0 && o.key.len > 0;
}

fn String describe(fault f) => f.description;

// One connection: handshake, then echo until the peer is done.
fn void serve(tls::Context* ctx, TcpSocket sock, bool verbose)
{
	TcpTransport tcp = tls::tcp_wrap(sock);
	defer (void)tcp.close();
	TlsTransport*? t = tls::accept(ctx, &tcp, 10 * time::SEC);
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

fn int main(String[] args)
{
	Options o = { .port = -1 };
	if (!parse(args, &o))
	{
		io::eprintn(USAGE);
		return 2;
	}
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
		if (catch err = sock) continue;
		serve(&ctx, sock, o.verbose);
	}
}
