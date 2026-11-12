module tls::wire_test;

import tls::wire;
import std::encoding::hex;

// Hex literal with optional spaces, decoded into temp memory.
fn char[] hx(String s)
{
	DString d = dstring::temp();
	foreach (c : s)
	{
		if (c != ' ') d.append_char(c);
	}
	return hex::tdecode(d.str_view())!!;
}

fn void test_wire_record_header_ok() @test
{
	RecordHeader h = wire::parse_record_header(hx("16 03 01 00 f8"))!!;
	assert(h.type == 22);
	assert(h.legacy_version == 0x0301);
	assert(h.length == 248);
}

fn void test_wire_record_header_ignores_body() @test
{
	// only the first five bytes matter
	RecordHeader h = wire::parse_record_header(hx("17 03 03 00 02 aa bb cc"))!!;
	assert(h.type == 23);
	assert(h.length == 2);
}

fn void test_wire_record_header_limits() @test
{
	RecordHeader a = wire::parse_record_header(hx("17 03 03 40 00"))!!;
	assert(a.length == 16384);
	RecordHeader b = wire::parse_record_header(hx("17 03 03 48 00"))!!;
	assert(b.length == 18432);
}

fn void test_wire_record_header_short() @test
{
	assert(@catch(wire::parse_record_header(hx("16 03 01 00"))) == wire::SHORT_INPUT);
	assert(@catch(wire::parse_record_header(hx(""))) == wire::SHORT_INPUT);
	assert(@catch(wire::parse_record_header(hx("16"))) == wire::SHORT_INPUT);
}

fn void test_wire_record_header_overflow() @test
{
	assert(@catch(wire::parse_record_header(hx("16 03 03 48 01 00 00 00 00 00 00 00 00 00 00"))) == wire::BAD_RECORD);
	assert(@catch(wire::parse_record_header(hx("17 03 03 ff ff"))) == wire::BAD_RECORD);
}

fn void test_wire_record_header_unknown_type() @test
{
	RecordHeader h = wire::parse_record_header(hx("63 03 03 00 01 00"))!!;
	assert(h.type == 0x63);
	assert(!wire::is_known_content_type(h.type));
}

fn void test_wire_record_header_raw_version() @test
{
	RecordHeader h = wire::parse_record_header(hx("16 02 00 00 01 00"))!!;
	assert(h.legacy_version == 0x0200);
	assert(h.length == 1);
}

fn void test_wire_record_header_zero_length() @test
{
	RecordHeader h = wire::parse_record_header(hx("16 03 01 00 00"))!!;
	assert(h.type == 22);
	assert(h.length == 0);
}

fn void test_wire_record_header_ccs() @test
{
	RecordHeader h = wire::parse_record_header(hx("14 03 03 00 01 01"))!!;
	assert(h.type == 20);
	assert(h.length == 1);
	assert(wire::is_known_content_type(h.type));
}

fn void test_wire_known_content_types() @test
{
	assert(!wire::is_known_content_type(19));
	assert(wire::is_known_content_type(20));
	assert(wire::is_known_content_type(21));
	assert(wire::is_known_content_type(22));
	assert(wire::is_known_content_type(23));
	assert(!wire::is_known_content_type(24));
	assert(!wire::is_known_content_type(0x47));
}

fn void check_alert_record(String record, char level, char description)
{
	char[] rec = hx(record);
	RecordHeader h = wire::parse_record_header(rec)!!;
	assert(h.type == 21);
	assert(h.length == 2);
	Alert a = wire::parse_alert(rec[5..])!!;
	assert(a.level == level);
	assert(a.description == description);
}

fn void test_wire_alert_v1_to_v5() @test
{
	check_alert_record("15 03 03 00 02 01 00", 1, 0);     // close_notify, warning
	check_alert_record("15 03 03 00 02 02 28", 2, 40);    // handshake_failure
	check_alert_record("15 03 03 00 02 02 46", 2, 70);    // protocol_version
	check_alert_record("15 03 03 00 02 02 30", 2, 48);    // unknown_ca
	check_alert_record("15 03 03 00 02 02 74", 2, 116);   // certificate_required
}

fn void test_wire_alert_wrong_length() @test
{
	assert(@catch(wire::parse_alert(hx("01"))) == wire::SHORT_INPUT);
	assert(@catch(wire::parse_alert(hx(""))) == wire::SHORT_INPUT);
	assert(@catch(wire::parse_alert(hx("01 00 00"))) == wire::BAD_RECORD);
}

fn void test_wire_alert_names() @test
{
	assert(wire::alert_name(0) == "close_notify");
	assert(wire::alert_name(10) == "unexpected_message");
	assert(wire::alert_name(20) == "bad_record_mac");
	assert(wire::alert_name(22) == "record_overflow");
	assert(wire::alert_name(40) == "handshake_failure");
	assert(wire::alert_name(42) == "bad_certificate");
	assert(wire::alert_name(44) == "certificate_revoked");
	assert(wire::alert_name(45) == "certificate_expired");
	assert(wire::alert_name(46) == "certificate_unknown");
	assert(wire::alert_name(47) == "illegal_parameter");
	assert(wire::alert_name(48) == "unknown_ca");
	assert(wire::alert_name(49) == "access_denied");
	assert(wire::alert_name(50) == "decode_error");
	assert(wire::alert_name(51) == "decrypt_error");
	assert(wire::alert_name(70) == "protocol_version");
	assert(wire::alert_name(71) == "insufficient_security");
	assert(wire::alert_name(80) == "internal_error");
	assert(wire::alert_name(86) == "inappropriate_fallback");
	assert(wire::alert_name(90) == "user_canceled");
	assert(wire::alert_name(109) == "missing_extension");
	assert(wire::alert_name(110) == "unsupported_extension");
	assert(wire::alert_name(112) == "unrecognized_name");
	assert(wire::alert_name(113) == "bad_certificate_status_response");
	assert(wire::alert_name(115) == "unknown_psk_identity");
	assert(wire::alert_name(116) == "certificate_required");
	assert(wire::alert_name(120) == "no_application_protocol");
}

fn void test_wire_alert_unknown_name() @test
{
	assert(wire::alert_name(1) == "unknown_alert");
	assert(wire::alert_name(255) == "unknown_alert");
}

fn void test_wire_alpn_b1() @test
{
	char[] out = wire::encode_alpn({ "mqtt" }, tmem)!!;
	assert(out == hx("04 6d 71 74 74"));
}

fn void test_wire_alpn_b2() @test
{
	char[] out = wire::encode_alpn({ "h2", "http/1.1" }, tmem)!!;
	assert(out == hx("02 68 32 08 68 74 74 70 2f 31 2e 31"));
	// the list inside the extension (V8): ext type 16, ext len 14, list len 12, then the names
	assert(out.len == 12);
}

fn void test_wire_alpn_b3() @test
{
	char[] out = wire::encode_alpn({ "x-amzn-mqtt-ca" }, tmem)!!;
	assert(out == hx("0e 78 2d 61 6d 7a 6e 2d 6d 71 74 74 2d 63 61"));
}

fn void test_wire_alpn_b4_empty_name() @test
{
	assert(@catch(wire::encode_alpn({ "" }, tmem)) == wire::BAD_ALPN);
	assert(@catch(wire::encode_alpn({ "h2", "" }, tmem)) == wire::BAD_ALPN);
}

fn void test_wire_alpn_b5_long_name() @test
{
	char[256] big;
	big[..] = 'a';
	String s256 = (String)big[..];
	assert(@catch(wire::encode_alpn({ s256 }, tmem)) == wire::BAD_ALPN);
	String s255 = (String)big[:255];
	char[] ok = wire::encode_alpn({ s255 }, tmem)!!;
	assert(ok.len == 256);
	assert(ok[0] == 255);
}

fn void test_wire_alpn_b6_empty_list() @test
{
	String[] none = {};
	char[] out = wire::encode_alpn(none, tmem)!!;
	assert(out.len == 0);
}

fn void test_wire_alpn_total_too_large() @test
{
	// 256 names of 255 bytes = 65536 bytes with prefixes: one byte too many
	char[255] name;
	name[..] = 'x';
	String s = (String)name[..];
	String[256] many;
	many[..] = s;
	assert(@catch(wire::encode_alpn(many[..], tmem)) == wire::BAD_ALPN);
	// 255 of them fit (65280 bytes)
	char[] ok = wire::encode_alpn(many[:255], tmem)!!;
	assert(ok.len == 255 * 256);
}
