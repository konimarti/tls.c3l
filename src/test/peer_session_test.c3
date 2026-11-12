module tls::peer_session_test;

import tls;
import tls::peer_support;
import tls::probe;
import std::time, std::io, std::thread, std::hash::sha256, std::encoding::hex;

fn ClientConfig cached(String extra_ca = "")
{
	return { .ca_file = peer_support::ca_file(), .session_cache = true };
}

// A first connection to `scenario` that ends with a usable session.
fn char[] first_session(String scenario)
{
	Probe p;
	defer p.release();
	p.start(scenario, cached(), "localhost");
	assert(p.done, "fault %s", p.result);
	assert(!p.conn.session_reused());
	// reading the answer is what delivers a TLS 1.3 ticket
	assert(p.request_page().starts_with("HTTP/1.0 200"));
	return p.conn.export_session()!!;
}

fn void check_resumption(String scenario, String version)
{
	char[] blob = first_session(scenario);
	defer
	{
		tls::wipe_session(blob);
		free(blob);
	}
	assert(blob.len > 32);
	Probe q;
	defer q.release();
	q.start(scenario, cached(), "localhost", blob);
	assert(!q.import_result, "import: %s", q.import_result);
	assert(q.done, "fault %s", q.result);
	assert(q.conn.version_name() == version);
	assert(q.conn.session_reused(), "a full handshake was done instead of resuming");
	// the resumed connection carries data
	assert(q.request_page().starts_with("HTTP/1.0 200"));
}

fn void test_peer_session_resumption_tls13() @test
{
	if (!peer_support::peers_ready()) return;
	check_resumption("resume13", "TLSv1.3");
}

fn void test_peer_session_resumption_tls12_with_tickets() @test
{
	if (!peer_support::peers_ready()) return;
	check_resumption("resume12", "TLSv1.2");
}

fn void test_peer_session_resumption_tls12_with_session_ids() @test
{
	if (!peer_support::peers_ready()) return;
	check_resumption("resume12id", "TLSv1.2");
}

fn void test_peer_session_blob_layout_and_wiping() @test
{
	if (!peer_support::peers_ready()) return;
	char[] blob = first_session("resume13");
	defer free(blob);
	// the first 32 bytes name the server the session belongs to
	assert(blob[:32] == sha256::hash("localhost")[..]);
	tls::wipe_session(blob);
	foreach (b : blob) assert(b == 0);
}

fn void test_peer_session_garbage_blobs_are_refused() @test
{
	if (!peer_support::peers_ready()) return;
	// a connection that has not started its handshake takes no network at all
	Context ctx = tls::new_client_context(&&cached())!!;
	defer ctx.free();
	Conn c = ctx.new_client_conn("localhost")!!;
	defer c.free();
	char[10] tiny;
	assert(@catch(c.import_session(tiny[..])) == tls::SESSION_INVALID);
	char[100] noise;
	noise[..] = 0x5a;
	assert(@catch(c.import_session(noise[..])) == tls::SESSION_INVALID);
	// right header, damaged session
	char[] good = first_session("resume13");
	defer
	{
		tls::wipe_session(good);
		free(good);
	}
	char[] damaged = mem::new_array(char, (sz)good.len);
	defer free(damaged);
	damaged[..] = good[..];
	for (usz i = 32; i < damaged.len; i++) damaged[i] = 0xff;
	assert(@catch(c.import_session(damaged)) == tls::SESSION_INVALID);
	// a refused session does not stop a full handshake
	Probe q;
	defer q.release();
	q.start("resume13", cached(), "localhost", damaged);
	assert(q.import_result == tls::SESSION_INVALID);
	assert(q.done);
	assert(!q.conn.session_reused());
}

fn void test_peer_session_from_another_name_is_refused() @test
{
	if (!peer_support::peers_ready()) return;
	char[] blob = first_session("resume13");
	defer
	{
		tls::wipe_session(blob);
		free(blob);
	}
	Probe p;
	defer p.release();
	// same peer, but verified as another name that the certificate also carries
	p.start("resume13", cached(), "test.example", blob);
	assert(p.import_result == tls::SESSION_INVALID);
	assert(p.done);
	assert(!p.conn.session_reused());
}

fn void test_peer_session_needs_the_cache_option() @test
{
	if (!peer_support::peers_ready()) return;
	ClientConfig plain = { .ca_file = peer_support::ca_file() };
	Probe p;
	defer p.release();
	p.start("resume13", plain, "localhost");
	assert(p.done);
	assert(@catch(p.conn.export_session()) == tls::CONFIG_INVALID);
	char[64] blob;
	assert(@catch(p.conn.import_session(blob[..])) == tls::CONFIG_INVALID);
}

fn void test_peer_session_export_and_import_at_the_wrong_time() @test
{
	if (!peer_support::peers_ready()) return;
	Context ctx = tls::new_client_context(&&cached())!!;
	defer ctx.free();
	Conn c = ctx.new_client_conn("localhost")!!;
	defer c.free();
	// nothing to export before the handshake
	assert(@catch(c.export_session()) == tls::NOT_CONNECTED);
	// and a session can no longer be offered once it is under way
	assert(!c.handshake()!!);
	char[64] blob;
	blob[:32][..] = sha256::hash("localhost")[..];
	assert(@catch(c.import_session(blob[..])) == tls::SESSION_INVALID);
}

fn void test_peer_session_resumption_still_checks_the_pin() @test
{
	if (!peer_support::peers_ready()) return;
	// the pin of the server certificate, computed outside the library
	char[] pin = hex_pin("SHA256_server");
	ClientConfig cfg = cached();
	cfg.pin_sha256 = pin;
	char[] blob;
	{
		Probe p;
		defer p.release();
		p.start("resume12", cfg, "localhost");
		assert(p.done, "fault %s", p.result);
		assert(p.request_page().starts_with("HTTP/1.0 200"));
		blob = p.conn.export_session()!!;
	}
	defer
	{
		tls::wipe_session(blob);
		free(blob);
	}
	// right pin: resumed
	{
		Probe q;
		defer q.release();
		q.start("resume12", cfg, "localhost", blob);
		assert(q.done, "fault %s", q.result);
		assert(q.conn.session_reused());
	}
	// wrong pin: the resumed connection is refused as well
	char[32] wrong;
	wrong[..] = pin[..];
	wrong[0] ^= 1;
	cfg.pin_sha256 = wrong[..];
	Probe r;
	defer r.release();
	r.start("resume12", cfg, "localhost", blob);
	assert(!r.done);
	assert(r.result == tls::PIN_MISMATCH, "fault %s", r.result);
}

fn char[] hex_pin(String key) => hex::tdecode(peer_support::state_value(key))!!;

// ---- renegotiation and key updates, driven through the peer's command pipe ----

fn void command(String scenario, String text)
{
	file::save(peer_support::state_value("CMD_".tconcat(scenario)), (char[])text)!!;
}

fn usz received_lines(String scenario, String needle)
{
	String path = peer_support::state_value("OUT").tconcat("/").tconcat(scenario).tconcat(".log");
	if (!file::is_file(path)) return 0;
	usz n = 0;
	foreach (line : ((String)file::load_temp(path)!!).tsplit("\n"))
	{
		if (line.starts_with("<<<") && line.contains(needle)) n++;
	}
	return n;
}

fn bool wait_for(String scenario, String needle, usz before)
{
	for (int i = 0; i < 60; i++)
	{
		if (received_lines(scenario, needle) > before) return true;
		thread::sleep_ms(50)!!;
	}
	return false;
}

fn void test_peer_renegotiation_request_is_declined() @test
{
	if (!peer_support::peers_ready()) return;
	usz before = received_lines("reneg", "no_renegotiation");
	Probe p;
	defer p.release();
	p.start("reneg", { .ca_file = peer_support::ca_file() }, "localhost");
	assert(p.done, "fault %s", p.result);
	assert(p.conn.version_name() == "TLSv1.2");
	// the server asks for a new handshake and then sends text: the connection carries on
	command("reneg", "r\n");
	thread::sleep_ms(200)!!;
	command("reneg", "after the request\n");
	char[128] buf;
	String got = p.receive(&buf, 5 * time::SEC);
	assert(got.contains("after the request"), "got '%s', fault %s", got, p.result);
	// we answered with a no_renegotiation warning and did not start a handshake of our own
	assert(wait_for("reneg", "no_renegotiation", before), "the server saw no refusal");
	p.send("still ours\n")!!;
	assert(!p.result);
}

fn void test_peer_key_update_requested_by_the_peer() @test
{
	if (!peer_support::peers_ready()) return;
	usz before = received_lines("keyupdate", "KeyUpdate");
	Probe p;
	defer p.release();
	p.start("keyupdate", { .ca_file = peer_support::ca_file() }, "localhost");
	assert(p.done, "fault %s", p.result);
	assert(p.conn.version_name() == "TLSv1.3");
	// the server updates its keys and asks us to do the same
	command("keyupdate", "K\n");
	thread::sleep_ms(200)!!;
	command("keyupdate", "after the update\n");
	char[128] buf;
	String got = p.receive(&buf, 5 * time::SEC);
	assert(got.contains("after the update"), "got '%s', fault %s", got, p.result);
	// both directions work with the new keys; our own KeyUpdate (the answer to the request) goes out with our next write
	p.send("and back\n")!!;
	assert(wait_for("keyupdate", "KeyUpdate", before), "the server saw no KeyUpdate from us");
	// application data is printed as it is, without the message marker
	bool arrived = false;
	for (int i = 0; i < 60 && !arrived; i++)
	{
		arrived = peer_support::log_count("keyupdate", "and back") > 0;
		if (!arrived) thread::sleep_ms(50)!!;
	}
	assert(arrived, "the server did not receive our data");
	command("keyupdate", "one more\n");
	String more = p.receive(&buf, 5 * time::SEC);
	assert(more.contains("one more"), "got '%s'", more);
}
