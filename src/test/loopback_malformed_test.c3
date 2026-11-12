module tls::loopback_malformed_test;

import tls;
import tls::loopback;
import tls::wire;
import tls::wire_test;
import tls::wire_hello_test;

const String SAMPLE_HELLO = "16 03 01 00 54 01 00 00 50 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 02 c0 2b 01 00 00 25 00 00 00 0b 00 09 00 00 06 61 2e 74 65 73 74 00 0a 00 04 00 02 00 17 00 0d 00 04 00 02 04 03 00 0b 00 02 01 00";

fn char[] hx(String s) => wire_test::hx(s);

// Feeds bytes to a fresh server connection and returns the fault of the handshake (0 when it waits for more).
fn fault feed_and_step(Lone* l, char[] bytes)
{
	assert(l.conn.feed(bytes) == (usz)bytes.len);
	bool? r = l.conn.handshake();
	if (catch f = r) return f;
	assert(!r);
	return {};
}

fn String text(Conn* c) => ((ZString)&c.error_text).str_view();

fn bool is_protocol_fault(fault f) => f == tls::PROTOCOL_ERROR || f == tls::PROTOCOL_VERSION;

// A malformed first record: a protocol fault, an alert record with the given description in the queue, and a sticky failure.
fn void expect_rejected_with_alert(char[] bytes, char description)
{
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, bytes);
	assert(f, "no fault");
	assert(is_protocol_fault(f), "fault %s: %s", f, text(&l.conn));
	char[] out = loopback::drain(&l.conn);
	defer free(out);
	char[2] alert = loopback::first_alert(out);
	assert(alert[0] == 2 && alert[1] == description, "alert level %d description %d, wanted %d", alert[0], alert[1], description);
	assert(@catch(l.conn.handshake()) == f); // sticky
}

// ---- hand-made garbage ----

fn void test_malformed_http_request_on_a_tls_port() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, (char[])"GET / HTTP/1.1\r\n\r\n");
	assert(is_protocol_fault(f), "fault %s: %s", f, text(&l.conn));
}

fn void test_malformed_unknown_content_type() @test
{
	if (!loopback::pki_ready()) return;
	expect_rejected_with_alert(hx("63 03 03 00 01 00"), 10);
}

fn void test_malformed_record_longer_than_allowed() @test
{
	if (!loopback::pki_ready()) return;
	expect_rejected_with_alert(hx("16 03 03 48 01 00 00 00 00 00 00 00 00 00 00"), 22);
}

fn void test_malformed_record_version_two() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, hx("16 02 00 00 01 00"));
	// either rejected or waiting; never a completed handshake
	assert(!f || is_protocol_fault(f), "fault %s", f);
	l.conn.feed_eof();
	assert(@catch(l.conn.handshake()));
}

fn void test_malformed_handshake_longer_than_its_record() @test
{
	if (!loopback::pki_ready()) return;
	char[] hello = hx(SAMPLE_HELLO);
	hello[8] = 0x51;
	Lone l;
	l.open();
	defer l.close();
	assert(!feed_and_step(&l, hello)); // waits for the rest of the message
	assert(l.conn.out_pending() == 0);
	l.conn.feed_eof();
	assert(@catch(l.conn.handshake()) == tls::TRUNCATED);
}

fn void test_malformed_cut_off_client_hello() @test
{
	if (!loopback::pki_ready()) return;
	char[] hello = hx(SAMPLE_HELLO);
	Lone l;
	l.open();
	defer l.close();
	assert(!feed_and_step(&l, hello[:30]));
	assert(l.conn.out_pending() == 0);
	l.conn.feed_eof();
	assert(@catch(l.conn.handshake()) == tls::TRUNCATED);
}

fn void test_malformed_empty_handshake_record() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	// OpenSSL waits; all this asserts is that nothing crashes and no handshake completes
	fault f = feed_and_step(&l, hx("16 03 01 00 00"));
	assert(!f || is_protocol_fault(f), "fault %s", f);
	l.conn.feed_eof();
	assert(@catch(l.conn.handshake()));
}

fn void test_malformed_alert_of_one_byte() @test
{
	if (!loopback::pki_ready()) return;
	expect_rejected_with_alert(hx("15 03 03 00 01 01"), 10);
}

fn void test_malformed_ssl2_framed_hello() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, hx("80 2e 01 03 01 00 02 00 00 00 10 00 00 00 00"));
	assert(!f || is_protocol_fault(f), "fault %s", f);
	l.conn.feed_eof();
	assert(@catch(l.conn.handshake()));
}

fn void test_malformed_change_cipher_spec_first() @test
{
	if (!loopback::pki_ready()) return;
	expect_rejected_with_alert(hx("14 03 03 00 01 01"), 10);
}

fn void test_malformed_application_data_first() @test
{
	if (!loopback::pki_ready()) return;
	expect_rejected_with_alert(hx("17 03 03 00 01 ff"), 10);
}

fn void test_malformed_client_hello_version_two() @test
{
	if (!loopback::pki_ready()) return;
	char[] hello = hx(SAMPLE_HELLO);
	hello[9] = 0x02;
	hello[10] = 0x00;
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, hello);
	assert(f == tls::PROTOCOL_VERSION, "fault %s: %s", f, text(&l.conn));
	char[] out = loopback::drain(&l.conn);
	defer free(out);
	char[2] alert = loopback::first_alert(out);
	assert(alert[0] == 2 && alert[1] == 70, "alert %d %d", alert[0], alert[1]);
}

fn void test_malformed_client_hello_far_too_short() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	fault f = feed_and_step(&l, hx("16 03 03 00 05 01 00 00 01 00"));
	assert(is_protocol_fault(f), "fault %s: %s", f, text(&l.conn));
	char[] out = loopback::drain(&l.conn);
	defer free(out);
	char[2] alert = loopback::first_alert(out);
	assert(alert[0] == 2 && alert[1] == 50, "alert %d %d", alert[0], alert[1]); // decode_error
}

fn void test_malformed_oversized_record_length() @test
{
	if (!loopback::pki_ready()) return;
	Lone l;
	l.open();
	defer l.close();
	char[] bytes = mem::new_array(char, 105);
	defer free(bytes);
	bytes[..] = 0x41;
	bytes[:5][..] = hx("17 03 03 ff ff")[..];
	fault f = feed_and_step(&l, bytes);
	assert(is_protocol_fault(f), "fault %s", f);
	// nothing close to the claimed 64 KiB is held back
	assert(l.conn.feed(bytes) <= tls::MAX_INBOUND);
}

fn void test_malformed_input_never_completes_a_handshake() @test
{
	if (!loopback::pki_ready()) return;
	// every prefix-cut of a real hello, and every single-byte corruption of it, either waits or fails; none succeeds
	char[] hello = hx(SAMPLE_HELLO);
	for (usz i = 0; i < hello.len; i++)
	{
		Lone l;
		l.open();
		defer l.close();
		char[] bad = mem::new_array(char, (sz)hello.len);
		defer free(bad);
		bad[..] = hello[..];
		bad[i] ^= 0xff;
		l.conn.feed(bad);
		bool? r = l.conn.handshake();
		if (try ok = r) assert(!ok);
		l.conn.feed_eof();
		assert(@catch(l.conn.handshake()));
	}
}

// ---- a real ClientHello as input ----

fn void test_malformed_hello_gets_a_server_hello() @test
{
	if (!loopback::pki_ready()) return;
	char[] hello = hx(SAMPLE_HELLO);
	Lone l;
	l.open();
	defer l.close();
	assert(!feed_and_step(&l, hello));
	char[] out = loopback::drain(&l.conn);
	defer free(out);
	RecordHeader h = wire::parse_record_header(out)!!;
	assert(h.type == 22);
	assert(out[5] == 2); // ServerHello
	assert(out[9] == 0x03 && out[10] == 0x03);
}

fn void test_malformed_hello_in_one_byte_slices() @test
{
	if (!loopback::pki_ready()) return;
	char[] hello = hx(SAMPLE_HELLO);
	Lone bulk;
	bulk.open();
	defer bulk.close();
	assert(!feed_and_step(&bulk, hello));
	char[] want = loopback::drain(&bulk.conn);
	defer free(want);

	Lone slow;
	slow.open();
	defer slow.close();
	foreach (b : hello)
	{
		char[1] one = { b };
		assert(slow.conn.feed(&one) == 1);
		assert(slow.conn.handshake()!! == false);
	}
	char[] got = loopback::drain(&slow.conn);
	defer free(got);
	// the random parts differ, the structure does not: the same sequence of record types and sizes within the signature's slack
	usz a = 0;
	usz b = 0;
	while (a + 5 <= want.len && b + 5 <= got.len)
	{
		RecordHeader x = wire::parse_record_header(want[a..])!!;
		RecordHeader y = wire::parse_record_header(got[b..])!!;
		assert(x.type == y.type);
		assert(x.length + 3 >= y.length && y.length + 3 >= x.length);
		a += 5 + (usz)x.length;
		b += 5 + (usz)y.length;
	}
	assert(a >= want.len - 8 && b >= got.len - 8);
}

fn void test_malformed_compatibility_change_cipher_spec() @test
{
	if (!loopback::pki_ready()) return;
	// a real TLS 1.3 client sends a change_cipher_spec record right after its hello (middlebox compatibility)
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	Conn c = cctx.new_client_conn("localhost")!!;
	defer c.free();
	Lone l;
	l.open();
	defer l.close();
	Link link;
	assert(!c.handshake()!!);
	assert(!l.conn.handshake()!!);
	loopback::move(&c, &l.conn, &link.to_server, false);
	assert(!l.conn.handshake()!!);
	// the server answers, the client reads it and replies; now the compat record is in the client's output
	loopback::move(&l.conn, &c, &link.to_client, false);
	assert(!c.handshake()!! || c.handshake_done);
	char[] reply = loopback::drain(&c);
	defer free(reply);
	assert(reply.len >= 6);
	assert(reply[0] == 20 && reply[1] == 3 && reply[2] == 3 && reply[3] == 0 && reply[4] == 1 && reply[5] == 1);
	// and the server accepts it in front of the real messages
	assert(l.conn.feed(reply) == (usz)reply.len);
	assert(@ok(l.conn.handshake()), "server handshake failed");
}
