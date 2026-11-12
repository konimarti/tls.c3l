// Test support: the peers started by tests/peer/run.py.
module tls::peer_support;

import tls;
import std::io, std::os::env;

const String STATE_FILE = "tests/peer/out/state.txt";

// True when the peers are up. Without the state file a test prints a note and passes, unless TLS_REQUIRE_PEERS is
// set (CI sets it): then missing peers fail the test.
fn bool peers_ready()
{
	if (file::is_file(STATE_FILE)) return true;
	bool required = @ok(env::tget_var("TLS_REQUIRE_PEERS"));
	assert(!required, "no peers and TLS_REQUIRE_PEERS is set: run python3 -I tests/peer/run.py start");
	io::printn("SKIP: no peers, run python3 -I tests/peer/run.py start");
	return false;
}

// The value of KEY in the state file. A missing key is a failure: the file exists, so the peer should too.
fn String state_value(String key)
{
	char[] data = file::load_temp(STATE_FILE)!!;
	String text = (String)data;
	String result = "";
	bool found = false;
	foreach (line : text.tsplit("\n"))
	{
		String[] kv = line.tsplit("=", 2);
		if (kv.len == 2 && kv[0] == key)
		{
			result = kv[1];
			found = true;
		}
	}
	assert(found, "state file has no %s", key);
	return result;
}

fn int peer_port(String scenario)
{
	String v = state_value("PORT_".tconcat(scenario));
	return (int)string::to_integer{int}(v)!!;
}

fn String ca_file() => state_value("CA");

// How many times `needle` occurs in the log file the peer of `scenario` writes.
fn usz log_count(String scenario, String needle)
{
	String path = state_value("OUT").tconcat("/").tconcat(scenario).tconcat(".log");
	if (!file::is_file(path)) return 0;
	String text = (String)file::load_temp(path)!!;
	usz count = 0;
	foreach (part : text.tsplit(needle)) count++;
	return count - 1;
}
