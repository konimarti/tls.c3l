module tls::accept_test;

import tls;
import tls::loopback;
import std::net, std::net::tcp, std::time, std::thread, std::io;

// A TLS echo server for one connection, running in its own thread with its own context.
struct EchoServer
{
	TcpServerSocket listener;
	ServerConfig cfg;
	fault failure;            // why the server side did not get through accept
	char[64] name_buf;        // the server name the client sent, copied out before the connection goes away
	usz name_len;
	char[32] fingerprint;     // of the client certificate, when there was one
	bool has_fingerprint;
	String alpn;              // static strings only
}

fn int serve_one(void* arg)
{
	EchoServer* srv = (EchoServer*)arg;
	Context? ctx = tls::new_server_context(&srv.cfg);
	if (catch err = ctx)
	{
		srv.failure = err;
		return 1;
	}
	defer ctx.free();
	TcpSocket? sock = tcp::accept(&srv.listener);
	if (catch err = sock)
	{
		srv.failure = err;
		return 1;
	}
	TcpTransport tcp = tls::tcp_wrap(sock);
	defer (void)tcp.close();
	TlsTransport*? t = tls::accept(&ctx, &tcp, 5 * time::SEC);
	if (catch err = t)
	{
		srv.failure = err;
		return 1;
	}
	defer t.free();
	String name = t.conn.requested_name();
	srv.name_len = min((usz)name.len, (usz)64);
	srv.name_buf[:srv.name_len][..] = ((char[])name)[:srv.name_len][..];
	if (t.conn.alpn_selected() == "h2") srv.alpn = "h2";
	char[]? fp = t.conn.peer_cert_sha256();
	if (try f = fp)
	{
		srv.fingerprint[:32][..] = f[:32][..];
		srv.has_fingerprint = true;
		free(f);
	}
	char[256] buf;
	while (true)
	{
		usz? n = t.read(&buf, 5 * time::SEC);
		if (catch err = n) break;
		if (@catch(t.write(buf[:n], 5 * time::SEC))) break;
	}
	(void)t.close();
	return 0;
}

struct Result
{
	fault client;            // why the client's connect failed
	EchoServer server;
	bool echoed;
	String alpn_client;
}

// One connection between a client and the server, each with its own context and thread.
fn void run(Result* r, ServerConfig scfg, ClientConfig ccfg, String name)
{
	r.server.cfg = scfg;
	r.server.listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)r.server.listener.close();
	ushort port = r.server.listener.local_port()!!;
	Thread th;
	th.create(&serve_one, &r.server)!!;

	Context cctx = tls::new_client_context(&ccfg)!!;
	defer cctx.free();
	TcpTransport tcp = tls::tcp_connect("127.0.0.1", port, 5 * time::SEC)!!;
	TlsTransport*? t = tls::connect(&cctx, &tcp, name, 5 * time::SEC);
	if (catch err = t)
	{
		r.client = err;
		(void)tcp.close();
	}
	else
	{
		if (t.conn.alpn_selected() == "h2") r.alpn_client = "h2";
		if (@ok(t.write("hello over tls\n", 5 * time::SEC)))
		{
			char[64] buf;
			usz? n = t.read(&buf, 5 * time::SEC);
			if (try m = n)
			{
				r.echoed = (String)buf[:m] == "hello over tls\n";
			}
			else
			{
				r.client = tls::TIMEOUT;
			}
		}
		(void)t.close();
		t.free();
	}
	th.join()!!;
}

fn void test_accept_echo_over_tcp() @test
{
	if (!loopback::pki_ready()) return;
	Result r;
	run(&r, loopback::server_cfg("server"), loopback::client_cfg(), "localhost");
	assert(!r.client);
	assert(!r.server.failure);
	assert(r.echoed);
	assert(((String)r.server.name_buf[:r.server.name_len]) == "localhost");
}

fn void test_accept_echo_tls12() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = loopback::client_cfg();
	cc.max_version = TLS_1_2;
	Result r;
	run(&r, loopback::server_cfg("server"), cc, "test.example");
	assert(!r.client);
	assert(r.echoed);
	assert(((String)r.server.name_buf[:r.server.name_len]) == "test.example");
}

fn void test_accept_with_client_certificate() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig sc = loopback::server_cfg("server");
	sc.client_ca_file = loopback::pki("ca.pem");
	ClientConfig cc = loopback::client_cfg();
	cc.client_cert_file = loopback::pki("client.pem");
	cc.client_key_file = loopback::pki("client.key");
	Result r;
	run(&r, sc, cc, "localhost");
	assert(!r.client);
	assert(r.echoed);
	// the server can see who connected: the fingerprint of the client certificate
	assert(r.server.has_fingerprint);
}

fn void test_accept_demands_the_client_certificate() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig sc = loopback::server_cfg("server");
	sc.client_ca_file = loopback::pki("ca.pem");
	Result r;
	run(&r, sc, loopback::client_cfg(), "localhost");
	assert(r.server.failure == tls::NO_PEER_CERT, "server fault %s", r.server.failure);
	assert(!r.echoed);
}

fn void test_accept_selects_an_application_protocol() @test
{
	if (!loopback::pki_ready()) return;
	ServerConfig sc = loopback::server_cfg("server");
	sc.alpn = { "h2" };
	ClientConfig cc = loopback::client_cfg();
	cc.alpn = { "http/1.1", "h2" };
	Result r;
	run(&r, sc, cc, "localhost");
	assert(r.alpn_client == "h2");
	assert(r.server.alpn == "h2");
	assert(r.echoed);
}

fn void test_accept_rejects_a_client_that_distrusts_the_server() @test
{
	if (!loopback::pki_ready()) return;
	ClientConfig cc = { .ca_file = loopback::pki("otherca.pem") };
	Result r;
	run(&r, loopback::server_cfg("server"), cc, "localhost");
	assert(r.client == tls::CERT_UNTRUSTED);
	// the server was told why it lost the client
	assert(r.server.failure == tls::ALERT_RECEIVED, "server fault %s", r.server.failure);
}
