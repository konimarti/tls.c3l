module tls::engine_test;

import tls;
import tls::ossl;
import tls::wire;
import tls::wire_hello_test;
import std::io;

// ---- helpers ----

fn Context client_ctx(ClientConfig cfg)
{
	return tls::new_client_context(&cfg)!!;
}

// Starts the handshake and returns the ClientHello the engine produced, plus its size on the wire.
fn ClientHelloInfo hello_of(Conn* c, usz* size = null)
{
	char[16384] buf;
	assert(!c.handshake()!!);
	usz n = c.take_out(&buf);
	assert(n > 5);
	if (size) *size = n;
	RecordHeader h = wire::parse_record_header(buf[:n])!!;
	assert(h.type == 22);
	assert((usz)h.length + 5 == n); // one record, nothing else queued
	return wire::parse_client_hello(buf[:n], tmem)!!;
}

fn bool has_version(ClientHelloInfo* info, ushort v)
{
	foreach (x : info.supported_versions)
	{
		if (x == v) return true;
	}
	return false;
}

fn bool has_group(ClientHelloInfo* info, ushort g)
{
	foreach (x : info.supported_groups)
	{
		if (x == g) return true;
	}
	return false;
}

// ---- the ClientHello we send ----

fn void test_engine_default_hello() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	usz size;
	ClientHelloInfo info = hello_of(&c, &size);
	assert(info.legacy_version == 0x0303);
	assert(info.server_name == "example.com");
	assert(has_version(&info, 0x0304));
	assert(has_version(&info, 0x0303));
	foreach (v : info.supported_versions) assert(v >= 0x0303);
	// the hello is sent once; asking again produces nothing new and still wants input
	assert(c.out_pending() == 0);
	assert(!c.handshake()!!);
	assert(c.out_pending() == 0);
	// OpenSSL 3.x ClientHello size, for the record: between a plain hello and one with a post-quantum key share
	io::printfn("default hello: %d bytes, groups %s, hybrid group 0x11ec present: %s", size, info.supported_groups, has_group(&info, 0x11ec));
	assert(size > 150 && size < 2500);
}

fn void test_engine_min_version_13() @test
{
	Context ctx = client_ctx({ .min_version = TLS_1_3 });
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(info.supported_versions == (ushort[]){ 0x0304 });
}

fn void test_engine_max_version_12() @test
{
	Context ctx = client_ctx({ .max_version = TLS_1_2 });
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(!has_version(&info, 0x0304));
	assert(info.legacy_version == 0x0303);
}

fn void test_engine_version_range_read_back() @test
{
	Context a = client_ctx({});
	defer a.free();
	assert(ossl::ctx_get_min_proto(a.handle) == 0x0303);
	assert(ossl::ctx_get_max_proto(a.handle) == 0x0304);
	Context b = client_ctx({ .min_version = TLS_1_3 });
	defer b.free();
	assert(ossl::ctx_get_min_proto(b.handle) == 0x0304);
	// a floor above the ceiling is a configuration error
	ClientConfig bad = { .min_version = TLS_1_3, .max_version = TLS_1_2 };
	assert(@catch(tls::new_client_context(&bad)) == tls::CONFIG_INVALID);
}

fn void test_engine_alpn_in_hello() @test
{
	Context ctx = client_ctx({ .alpn = { "h2", "http/1.1" } });
	defer ctx.free();
	assert(ctx.has_alpn);
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(info.alpn.len == 2);
	assert(info.alpn[0] == "h2");
	assert(info.alpn[1] == "http/1.1");
}

fn void test_engine_no_alpn_no_extension() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	assert(!ctx.has_alpn);
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(info.alpn.len == 0);
}

fn void test_engine_alpn_bad_lists() @test
{
	char[256] big;
	big[..] = 'a';
	ClientConfig empty_name = { .alpn = { "h2", "" } };
	assert(@catch(tls::new_client_context(&empty_name)) == tls::CONFIG_INVALID);
	ClientConfig long_name = { .alpn = { (String)big[..] } };
	assert(@catch(tls::new_client_context(&long_name)) == tls::CONFIG_INVALID);
}

fn void test_engine_ip_literals_send_no_sni() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	String[3] ips = { "127.0.0.1", "::1", "2001:db8::1" };
	foreach (ip : ips)
	{
		Conn c = ctx.new_client_conn(ip)!!;
		defer c.free();
		ClientHelloInfo info = hello_of(&c);
		assert(info.server_name.len == 0);
	}
}

fn void test_engine_trailing_dot_is_not_sent() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("test.example.")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(info.server_name == "test.example");
}

fn void test_engine_groups_override() @test
{
	Context ctx = client_ctx({ .groups = "P-256" });
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	ClientHelloInfo info = hello_of(&c);
	assert(!has_group(&info, 0x11ec));
	assert(has_group(&info, 0x0017));
	ClientConfig bad = { .groups = "no-such-group" };
	assert(@catch(tls::new_client_context(&bad)) == tls::CONFIG_INVALID);
}

fn void test_engine_name_checks_by_mode() @test
{
	// FULL verification needs a name
	Context full = client_ctx({});
	defer full.free();
	assert(@catch(full.new_client_conn("")) == tls::CONFIG_INVALID);
	// the other modes may go without one: no SNI, no name check
	Context chain = client_ctx({ .verify = CHAIN_ONLY });
	defer chain.free();
	Conn anon = chain.new_client_conn("")!!;
	defer anon.free();
	assert(hello_of(&anon).server_name.len == 0);
	// but a name that is given is still validated and still sent
	Conn named = chain.new_client_conn("example.com")!!;
	defer named.free();
	assert(hello_of(&named).server_name == "example.com");
	assert(@catch(chain.new_client_conn("bad name")) == tls::CONFIG_INVALID);
}

// ---- host names ----

fn void test_validate_server_name_table() @test
{
	assert(@catch(tls::validate_server_name("")) == tls::CONFIG_INVALID);
	char[254] long_name;
	long_name[..] = 'a';
	long_name[10] = '.'; // keeps every label short; only the total length is too big
	long_name[70] = '.';
	long_name[130] = '.';
	long_name[190] = '.';
	assert(@catch(tls::validate_server_name((String)long_name[..])) == tls::CONFIG_INVALID);
	assert(@catch(tls::validate_server_name("a\0b.example")) == tls::CONFIG_INVALID);
	assert(@catch(tls::validate_server_name("bücher.example")) == tls::CONFIG_INVALID);   // U-label
	assert(@catch(tls::validate_server_name(".test.example")) == tls::CONFIG_INVALID);          // empty label
	assert(@catch(tls::validate_server_name("a..example")) == tls::CONFIG_INVALID);
	assert(@catch(tls::validate_server_name(".")) == tls::CONFIG_INVALID);
	assert(@catch(tls::validate_server_name("*.test.example")) == tls::CONFIG_INVALID);
	assert(@catch(tls::validate_server_name("has space.example")) == tls::CONFIG_INVALID);
	char[64] label;
	label[..] = 'a';
	assert(@catch(tls::validate_server_name((String)label[..])) == tls::CONFIG_INVALID);        // label of 64
	assert(tls::validate_server_name((String)label[:63])!!.kind == DNS);

	NamePlan trailing = tls::validate_server_name("test.example.")!!;
	assert(trailing.name == "test.example");
	assert(trailing.kind == DNS);
	assert(tls::validate_server_name("xn--bcher-kva.example")!!.kind == DNS);
	assert(tls::validate_server_name("my_host-1.local")!!.kind == DNS);
	assert(tls::validate_server_name("localhost")!!.kind == DNS);

	assert(tls::validate_server_name("127.0.0.1")!!.kind == IPV4);
	assert(tls::validate_server_name("10.20.30.40")!!.kind == IPV4);
	assert(tls::validate_server_name("999.1.1.1")!!.kind == DNS);   // not an address: an ordinary (odd) name
	assert(tls::validate_server_name("1.2.3")!!.kind == DNS);
	assert(tls::validate_server_name("::1")!!.kind == IPV6);
	assert(tls::validate_server_name("2001:db8::1")!!.kind == IPV6);
	assert(@catch(tls::validate_server_name("fe80::1%eth0")) == tls::CONFIG_INVALID);
}

// ---- configuration faults ----

fn void test_engine_config_faults() @test
{
	ClientConfig missing_ca = { .ca_file = "/nonexistent/ca.pem" };
	assert(@catch(tls::new_client_context(&missing_ca)) == tls::CA_LOAD_FAILED);
	ClientConfig garbage_ca = { .ca_file = "src/test/fixtures/garbage.pem" };
	assert(@catch(tls::new_client_context(&garbage_ca)) == tls::CA_LOAD_FAILED);

	ClientConfig cert_only = { .client_cert_file = "/nonexistent/client.pem" };
	assert(@catch(tls::new_client_context(&cert_only)) == tls::CONFIG_INVALID);
	ClientConfig key_only = { .client_key_file = "/nonexistent/client.key" };
	assert(@catch(tls::new_client_context(&key_only)) == tls::CONFIG_INVALID);
	ClientConfig missing_cert = { .client_cert_file = "/nonexistent/client.pem", .client_key_file = "/nonexistent/client.key" };
	assert(@catch(tls::new_client_context(&missing_cert)) == tls::CERT_LOAD_FAILED);
	ClientConfig garbage_cert = { .client_cert_file = "src/test/fixtures/garbage.pem", .client_key_file = "src/test/fixtures/garbage.pem" };
	assert(@catch(tls::new_client_context(&garbage_cert)) == tls::CERT_LOAD_FAILED);

	char[31] short_pin;
	ClientConfig bad_pin = { .pin_sha256 = short_pin[..] };
	assert(@catch(tls::new_client_context(&bad_pin)) == tls::CONFIG_INVALID);
	ClientConfig pinned_without_pin = { .verify = PINNED_ONLY };
	assert(@catch(tls::new_client_context(&pinned_without_pin)) == tls::CONFIG_INVALID);
	ClientConfig bad_ciphers = { .cipher_list = "NOT-A-CIPHER" };
	assert(@catch(tls::new_client_context(&bad_ciphers)) == tls::CONFIG_INVALID);
	ClientConfig bad_suites = { .ciphersuites = "NOT-A-SUITE" };
	assert(@catch(tls::new_client_context(&bad_suites)) == tls::CONFIG_INVALID);
	ClientConfig neg_depth = { .max_chain_depth = -1 };
	assert(@catch(tls::new_client_context(&neg_depth)) == tls::CONFIG_INVALID);
}

fn void test_engine_valid_pin_is_kept() @test
{
	char[32] pin;
	pin[..] = 0x5a;
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ClientConfig cfg = { .verify = PINNED_ONLY, .pin_sha256 = pin[..] };
	Context ctx = tls::new_client_context(&cfg, &ta)!!;
	assert(ctx.pin_sha256 == pin[..]);
	assert(ctx.pin_sha256.ptr != pin[..].ptr); // a copy, the config may go away
	ctx.free();
	ctx.free(); // second free is harmless
	assert(!ta.has_leaks());
}

// ---- trust and verification settings ----

fn void test_engine_trust_sources() @test
{
	// no custom CA: the system store is used
	Context sys = client_ctx({});
	defer sys.free();
	assert(sys.system_roots_loaded);
	// a configured CA replaces it (a directory loads lazily, so any directory will do for this check)
	Context custom = client_ctx({ .ca_dir = "src/test/fixtures" });
	defer custom.free();
	assert(!custom.system_roots_loaded);
	// unless both are asked for
	Context both = client_ctx({ .ca_dir = "src/test/fixtures", .also_system_roots = true });
	defer both.free();
	assert(both.system_roots_loaded);
	// modes that do not verify a chain load no trust store at all
	char[32] pin;
	Context pinned = client_ctx({ .verify = PINNED_ONLY, .pin_sha256 = pin[..] });
	defer pinned.free();
	assert(!pinned.system_roots_loaded);
	Context insecure = client_ctx({ .verify = INSECURE_NONE });
	defer insecure.free();
	assert(!insecure.system_roots_loaded);
}

fn void test_engine_verify_modes() @test
{
	char[32] pin;
	Context full = client_ctx({});
	defer full.free();
	assert(ossl::ssl_ctx_get_verify_mode(full.handle) == ossl::SSL_VERIFY_PEER);
	Context chain = client_ctx({ .verify = CHAIN_ONLY });
	defer chain.free();
	assert(ossl::ssl_ctx_get_verify_mode(chain.handle) == ossl::SSL_VERIFY_PEER);
	Context pinned = client_ctx({ .verify = PINNED_ONLY, .pin_sha256 = pin[..] });
	defer pinned.free();
	assert(ossl::ssl_ctx_get_verify_mode(pinned.handle) == ossl::SSL_VERIFY_NONE);
	Context insecure = client_ctx({ .verify = INSECURE_NONE });
	defer insecure.free();
	assert(ossl::ssl_ctx_get_verify_mode(insecure.handle) == ossl::SSL_VERIFY_NONE);
}

fn void test_engine_key_loading_cannot_prompt() @test
{
	// every context installs a non-NULL passphrase before any key is loaded: the default callback then never
	// reads from the terminal. Without a controlling terminal a prompt would fail fast anyway, so the cause is asserted.
	Context ctx = client_ctx({});
	defer ctx.free();
	assert(ossl::ssl_ctx_get_default_passwd_cb_userdata(ctx.handle) != null);
}

// ---- guards and sticky failure ----

fn void test_engine_guards_before_handshake() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	char[8] buf;
	assert(@catch(c.write("hi")) == tls::NOT_CONNECTED);
	assert(@catch(c.write("")) == tls::NOT_CONNECTED);
	assert(@catch(c.read(&buf)) == tls::NOT_CONNECTED);
	// a refused call is not a failure: the handshake can still start
	assert(!c.handshake()!!);
	// close_notify before the handshake finished sends nothing
	c.close_notify()!!;
	assert(c.out_pending() > 0); // only the hello
	char[16384] sink;
	c.take_out(&sink);
	c.close_notify()!!;
	assert(c.out_pending() == 0);
}

fn void test_engine_http_reply_is_a_protocol_error() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	hello_of(&c);
	String reply = "HTTP/1.1 400 Bad Request\r\n\r\n";
	assert(c.feed((char[])reply) == reply.len);
	fault f = @catch(c.handshake());
	assert(f == tls::PROTOCOL_ERROR || f == tls::PROTOCOL_VERSION);
	// sticky: every later call reports the same fault and calls nothing in OpenSSL
	char[8] buf;
	assert(@catch(c.handshake()) == f);
	assert(@catch(c.read(&buf)) == f);
	assert(@catch(c.write("x")) == f);
	assert(c.error_text[0] != 0); // the OpenSSL text was kept for diagnostics
	// the queue can still be drained and close_notify is only a drain
	char[1024] sink;
	while (c.take_out(&sink) > 0) {}
	c.close_notify()!!;
	assert(c.out_pending() == 0);
	assert(@catch(c.handshake()) == f);
}

fn void test_engine_old_server_hello_is_a_version_fault() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	hello_of(&c);
	// ServerHello that selects TLS 1.1 (record and legacy version 0x0302) without supported_versions
	char[] body = {
		0x03, 0x02,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		0x00,
		0xc0, 0x2b,
		0x00,
	};
	char[] msg = { 0x02, 0x00, 0x00, (char)body.len };
	char[] record = { 0x16, 0x03, 0x02, 0x00, (char)(body.len + 4) };
	char[] all = wire_hello_test::cat(wire_hello_test::cat(record, msg), body);
	assert(c.feed(all) == (usz)all.len);
	assert(@catch(c.handshake()) == tls::PROTOCOL_VERSION);
}

fn void test_engine_eof_during_handshake_is_truncation() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	hello_of(&c);
	c.feed_eof();
	assert(@catch(c.handshake()) == tls::TRUNCATED);
	assert(@catch(c.handshake()) == tls::TRUNCATED);
}

fn void test_engine_feed_is_capped() @test
{
	Context ctx = client_ctx({});
	defer ctx.free();
	Conn c = ctx.new_client_conn("example.com")!!;
	defer c.free();
	char[] mib = mem::new_array(char, 1024 * 1024);
	defer free(mib);
	mib[..] = 0x16;
	usz first = c.feed(mib);
	assert(first == tls::MAX_INBOUND);
	assert(c.feed(mib) == 0);        // full: the caller has to let the engine consume first
	assert(c.feed(mib[:0]) == 0);
}

// ---- lifetime ----

fn void test_engine_double_free() @test
{
	Context ctx = client_ctx({});
	Conn c = ctx.new_client_conn("example.com")!!;
	c.free();
	c.free();
	assert(c.out_pending() == 0);
	assert(c.feed("x") == 0);
	ctx.free();
	ctx.free();
}

fn void test_engine_create_free_cycles() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	char[32] pin;
	pin[..] = 1;
	for (int i = 0; i < 1000; i++)
	{
		ClientConfig cfg = { .verify = PINNED_ONLY, .pin_sha256 = pin[..], .alpn = { "mqtt" } };
		Context ctx = tls::new_client_context(&cfg, &ta)!!;
		Conn c = ctx.new_client_conn("broker.example", &ta)!!;
		c.free();
		ctx.free();
	}
	assert(!ta.has_leaks());
	assert(ta.allocation_count() == 0);
}

fn void test_engine_failed_construction_releases_everything() @test
{
	// each of these fails after the context object or some of its settings exist
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	for (int i = 0; i < 200; i++)
	{
		ClientConfig bad = { .ca_file = "/nonexistent/ca.pem" };
		assert(@catch(tls::new_client_context(&bad, &ta)) == tls::CA_LOAD_FAILED);
		ClientConfig bad_alpn = { .alpn = { "" } };
		assert(@catch(tls::new_client_context(&bad_alpn, &ta)) == tls::CONFIG_INVALID);
		ClientConfig bad_groups = { .groups = "nope" };
		assert(@catch(tls::new_client_context(&bad_groups, &ta)) == tls::CONFIG_INVALID);
	}
	assert(!ta.has_leaks());
}
