module tls::wire_hello_test;

import tls::wire;
import tls::wire_test;

const String V7_HEX = "16 03 01 00 54 01 00 00 50 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 02 c0 2b 01 00 00 25 00 00 00 0b 00 09 00 00 06 61 2e 74 65 73 74 00 0a 00 04 00 02 00 17 00 0d 00 04 00 02 04 03 00 0b 00 02 01 00";

// Byte builder for hellos made from fields.
struct Buf
{
	DString d;
}

fn Buf buf_new() => { .d = dstring::temp() };
fn void Buf.u8(&self, usz v) => self.d.append_char((char)v);
fn void Buf.u16(&self, usz v) { self.u8(v >> 8 & 0xff); self.u8(v & 0xff); }
fn void Buf.raw(&self, char[] b) { foreach (c : b) self.d.append_char(c); }
fn char[] Buf.bytes(&self) => self.d.str_view();

// ClientHello record from fields. `exts` is the extension block WITHOUT its 2-byte length, null = no extension block at all.
fn char[] build_hello(ushort version, ushort[] suites, char[] exts, bool with_exts)
{
	Buf body = buf_new();
	body.u16(version);
	for (usz i = 0; i < 32; i++) body.u8(i);       // random
	body.u8(0);                                    // session id
	body.u16(suites.len * 2);
	foreach (s : suites) body.u16(s);
	body.u8(1);
	body.u8(0);                                    // null compression
	if (with_exts)
	{
		body.u16(exts.len);
		body.raw(exts);
	}
	Buf hs = buf_new();
	hs.u8(1);
	hs.u8(body.bytes().len >> 16);
	hs.u16(body.bytes().len & 0xffff);
	hs.raw(body.bytes());
	Buf rec = buf_new();
	rec.u8(22);
	rec.u16(0x0301);
	rec.u16(hs.bytes().len);
	rec.raw(hs.bytes());
	return rec.bytes();
}

fn char[] ext(ushort type, char[] data)
{
	Buf b = buf_new();
	b.u16(type);
	b.u16(data.len);
	b.raw(data);
	return b.bytes();
}

fn char[] cat(char[] a, char[] b)
{
	Buf x = buf_new();
	x.raw(a);
	x.raw(b);
	return x.bytes();
}

fn char[] hx(String s) => wire_test::hx(s);

fn void test_hello_v7_golden() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ClientHelloInfo info = wire::parse_client_hello(hx(V7_HEX), &ta)!!;
	assert(info.legacy_version == 0x0303);
	assert(info.server_name == "a.test");
	assert(info.cipher_suites == (ushort[]){ 0xc02b });
	assert(info.supported_groups == (ushort[]){ 0x0017 });
	assert(info.supported_versions.len == 0);
	assert(info.alpn.len == 0);
	info.free();
	assert(!ta.has_leaks());
}

fn void test_hello_v7_fixture_file() @test
{
	// the same bytes as the checked-in fixture file
	String file = (String)$embed("fixtures/clienthello_v7.hex");
	assert(hx(file.trim()) == hx(V7_HEX));
}

fn void test_hello_v7_built() @test
{
	Buf e = buf_new();
	// server_name a.test, supported_groups, signature_algorithms, ec_point_formats: as in the golden bytes
	e.raw(ext(0, hx("00 09 00 00 06 61 2e 74 65 73 74")));
	e.raw(ext(10, hx("00 02 00 17")));
	e.raw(ext(13, hx("00 02 04 03")));
	e.raw(ext(11, hx("01 00")));
	char[] built = build_hello(0x0303, { 0xc02b }, e.bytes(), true);
	assert(built == hx(V7_HEX));
	ClientHelloInfo info = wire::parse_client_hello(built, tmem)!!;
	assert(info.server_name == "a.test");
}

fn void test_hello_extension_vectors() @test
{
	// V9: SNI extension for example.com, V8: ALPN h2,http/1.1, V10: supported_versions
	Buf e = buf_new();
	e.raw(hx("00 00 00 10 00 0e 00 00 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d"));
	e.raw(hx("00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31"));
	e.raw(hx("00 2b 00 05 04 03 04 03 03"));
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301, 0xc02b }, e.bytes(), true), &ta)!!;
	assert(info.server_name == "example.com");
	assert(info.alpn.len == 2);
	assert(info.alpn[0] == "h2");
	assert(info.alpn[1] == "http/1.1");
	assert(info.supported_versions == (ushort[]){ 0x0304, 0x0303 });
	assert(info.cipher_suites == (ushort[]){ 0x1301, 0xc02b });
	info.free();
	assert(!ta.has_leaks());
}

fn void test_hello_groups_pq() @test
{
	Buf e = buf_new();
	e.raw(ext(10, hx("00 06 11 ec 00 1d 00 17")));
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, e.bytes(), true), tmem)!!;
	assert(info.supported_groups == (ushort[]){ 0x11ec, 0x001d, 0x0017 });
}

fn void test_hello_no_extensions() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x002f, 0x0035 }, {}, false), &ta)!!;
	assert(info.server_name.len == 0);
	assert(info.alpn.len == 0);
	assert(info.supported_versions.len == 0);
	assert(info.cipher_suites == (ushort[]){ 0x002f, 0x0035 });
	info.free();
	assert(!ta.has_leaks());
}

fn void test_hello_empty_extension_block() @test
{
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, {}, true), tmem)!!;
	assert(info.server_name.len == 0);
}

fn void test_hello_unknown_extension_ignored() @test
{
	Buf e = buf_new();
	e.raw(ext(0x4a4a, hx("de ad be ef")));
	e.raw(ext(0, hx("00 09 00 00 06 61 2e 74 65 73 74")));
	e.raw(ext(0xff01, hx("00")));
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, e.bytes(), true), tmem)!!;
	assert(info.server_name == "a.test");
}

fn void test_hello_zero_length_sni_list() @test
{
	Buf e = buf_new();
	e.raw(ext(0, hx("00 00")));
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, e.bytes(), true), tmem)!!;
	assert(info.server_name.len == 0);
}

fn void test_hello_m6_lying_length() @test
{
	// V7 with the handshake length claiming one byte more than the record carries
	char[] bad = hx(V7_HEX);
	bad[8] = 0x51;
	assert(@catch(wire::parse_client_hello(bad, tmem)) == wire::BAD_HANDSHAKE);
}

fn void test_hello_m14_too_short() @test
{
	assert(@catch(wire::parse_client_hello(hx("16 03 03 00 05 01 00 00 01 00"), tmem)) == wire::BAD_HANDSHAKE);
}

fn void test_hello_truncated() @test
{
	char[] v7 = hx(V7_HEX);
	for (usz n = 0; n < v7.len; n++)
	{
		assert(@catch(wire::parse_client_hello(v7[:n], tmem)) == wire::SHORT_INPUT);
	}
}

fn void test_hello_trailing_bytes_after_record_ignored() @test
{
	char[] more = cat(hx(V7_HEX), hx("17 03 03 00 01 ff"));
	ClientHelloInfo info = wire::parse_client_hello(more, tmem)!!;
	assert(info.server_name == "a.test");
}

fn void test_hello_lying_extension_length() @test
{
	// extension claims 0x20 bytes but only 4 follow inside the block
	char[] e = hx("00 00 00 20 00 09 00 00");
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, e, true), tmem)) == wire::BAD_HANDSHAKE);
}

fn void test_hello_extension_block_length_mismatch() @test
{
	// V7 with the extension block length one too large
	char[] v7 = hx(V7_HEX);
	usz at = v7.len - 37 - 2;
	assert(v7[at] == 0 && v7[at + 1] == 0x25);
	v7[at + 1] = 0x26;
	assert(@catch(wire::parse_client_hello(v7, tmem)) == wire::BAD_HANDSHAKE);
}

fn void test_hello_wrong_record_or_message_type() @test
{
	char[] app = hx(V7_HEX);
	app[0] = 23;
	assert(@catch(wire::parse_client_hello(app, tmem)) == wire::BAD_HANDSHAKE);
	char[] sh = hx(V7_HEX);
	sh[5] = 2; // server_hello
	assert(@catch(wire::parse_client_hello(sh, tmem)) == wire::BAD_HANDSHAKE);
}

fn void test_hello_bad_record_header() @test
{
	assert(@catch(wire::parse_client_hello(hx("16 03 03 48 01 00 00"), tmem)) == wire::BAD_RECORD);
}

fn void test_hello_malformed_fields_release_memory() @test
{
	// cipher suites with an odd length, ALPN with an empty name, a failure after allocations (lying second ALPN name)
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();

	Buf odd = buf_new();
	odd.u16(0x0303);
	for (usz i = 0; i < 32; i++) odd.u8(i);
	odd.u8(0);
	odd.u16(3);
	odd.raw(hx("13 01 13"));
	odd.u8(1);
	odd.u8(0);
	Buf hs = buf_new();
	hs.u8(1);
	hs.u8(0);
	hs.u16(odd.bytes().len);
	hs.raw(odd.bytes());
	Buf rec = buf_new();
	rec.u8(22);
	rec.u16(0x0303);
	rec.u16(hs.bytes().len);
	rec.raw(hs.bytes());
	assert(@catch(wire::parse_client_hello(rec.bytes(), &ta)) == wire::BAD_HANDSHAKE);

	char[] empty_name = ext(16, hx("00 04 02 68 32 00"));
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, empty_name, true), &ta)) == wire::BAD_HANDSHAKE);

	// SNI parsed (allocated) first, then the groups extension is malformed (odd length)
	Buf e = buf_new();
	e.raw(ext(0, hx("00 09 00 00 06 61 2e 74 65 73 74")));
	e.raw(ext(10, hx("00 03 00 17 00")));
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, e.bytes(), true), &ta)) == wire::BAD_HANDSHAKE);

	assert(!ta.has_leaks());
}

fn void test_hello_duplicate_extensions_rejected() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	char[] sni_a = ext(0, hx("00 09 00 00 06 61 2e 74 65 73 74"));
	char[] sni_b = ext(0, hx("00 09 00 00 06 62 2e 74 65 73 74"));
	char[] groups = ext(10, hx("00 02 00 17"));
	char[] groups_empty = ext(10, hx("00 00"));
	char[] versions = ext(43, hx("02 03 04"));
	char[] versions_empty = ext(43, hx("00"));
	char[] alpn = ext(16, hx("00 03 02 68 32"));

	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(sni_a, sni_b), true), &ta)) == wire::BAD_HANDSHAKE);
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(groups, groups), true), &ta)) == wire::BAD_HANDSHAKE);
	// an empty first extension must not let a second one through
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(groups_empty, groups), true), &ta)) == wire::BAD_HANDSHAKE);
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(versions, versions), true), &ta)) == wire::BAD_HANDSHAKE);
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(versions_empty, versions), true), &ta)) == wire::BAD_HANDSHAKE);
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, cat(alpn, alpn), true), &ta)) == wire::BAD_HANDSHAKE);
	assert(!ta.has_leaks());
}

fn void test_hello_two_host_names_in_one_list_rejected() @test
{
	// one server_name extension whose list holds two host_name entries
	char[] list = hx("00 12 00 00 06 61 2e 74 65 73 74 00 00 06 62 2e 74 65 73 74");
	assert(@catch(wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, ext(0, list), true), tmem)) == wire::BAD_HANDSHAKE);
	// a host_name next to an entry of another name type is fine, the other type is skipped
	char[] mixed = hx("00 0d 01 00 01 aa 00 00 06 61 2e 74 65 73 74");
	ClientHelloInfo info = wire::parse_client_hello(build_hello(0x0303, { 0x1301 }, ext(0, mixed), true), tmem)!!;
	assert(info.server_name == "a.test");
}
