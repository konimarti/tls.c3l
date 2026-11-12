module tls::adapter_test;

import tls;
import tls::engine_transport;
import tls::loopback;
import std::time;

// A client TlsTransport talking to a server engine in the same process.
struct Rig
{
	ServerEnd end;
	Context cctx;
	TlsTransport* t;
}

fn void Rig.open(&self, ClientConfig cc, Duration handshake_timeout = time::DURATION_ZERO)
{
	self.end.open(loopback::server_cfg("server"));
	self.cctx = tls::new_client_context(&cc)!!;
	self.t = tls::connect(&self.cctx, &self.end, "localhost", handshake_timeout)!!;
}

fn void Rig.close(&self)
{
	if (self.t) self.t.free();
	self.cctx.free();
	self.end.release();
}

fn void test_adapter_data_reaches_the_server() @test
{
	if (!loopback::pki_ready()) return;
	Rig r;
	r.open(loopback::client_cfg());
	defer r.close();
	r.t.write("hello ", time::SEC)!!;
	r.t.write("world", time::SEC)!!;
	assert(r.end.text() == "hello world");
}

fn void test_adapter_failed_write_poisons_the_stream() @test
{
	if (!loopback::pki_ready()) return;
	Rig r;
	r.open(loopback::client_cfg());
	defer r.close();
	r.t.write("first", time::SEC)!!;
	r.end.fail_writes = 1;
	// the encrypted record was taken out of the engine and the transport failed to take it: the stream is lost
	assert(@catch(r.t.write("second", time::SEC)) == tls::TIMEOUT);
	// from here every call reports that, instead of sending records that leave a gap in the sequence
	char[8] buf;
	assert(@catch(r.t.write("third", time::SEC)) == tls::TIMEOUT);
	assert(@catch(r.t.read(&buf, 10 * time::MS)) == tls::TIMEOUT);
	assert(r.end.text() == "first");
}
