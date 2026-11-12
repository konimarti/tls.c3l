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

fn void test_adapter_handshake_timeout_is_a_total() @test
{
	if (!loopback::pki_ready()) return;
	ServerEnd end;
	end.open(loopback::server_cfg("server"));
	defer end.release();
	// the peer answers, but one byte per read and slowly: each wait is short, the sum is not
	end.read_limit = 1;
	end.read_delay_ms = 5;
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	TlsTransport*? t = tls::connect(&cctx, &end, "localhost", 150 * time::MS);
	assert(@catch(t) == tls::TIMEOUT);
	// without a limit the same peer gets through
	ServerEnd patient;
	patient.open(loopback::server_cfg("server"));
	defer patient.release();
	patient.read_limit = 64;
	TlsTransport* ok = tls::connect(&cctx, &patient, "localhost")!!;
	ok.free();
}

fn void test_adapter_failed_connect_releases_everything() @test
{
	if (!loopback::pki_ready()) return;
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	ServerEnd end;
	end.open(loopback::server_cfg("server"));
	defer end.release();
	Context cctx = tls::new_client_context(&&loopback::client_cfg())!!;
	defer cctx.free();
	// a name the connection cannot be made for, and a handshake that fails on the host name
	assert(@catch(tls::connect(&cctx, &end, "bad name", time::DURATION_ZERO, &ta)) == tls::CONFIG_INVALID);
	assert(@catch(tls::connect(&cctx, &end, "wrong.example", time::DURATION_ZERO, &ta)) == tls::HOSTNAME_MISMATCH);
	assert(ta.allocation_count() == 0);
	// and a success followed by free
	ServerEnd end2;
	end2.open(loopback::server_cfg("server"));
	defer end2.release();
	TlsTransport* t = tls::connect(&cctx, &end2, "localhost", time::DURATION_ZERO, &ta)!!;
	t.free();
	assert(ta.allocation_count() == 0);
}

fn void test_adapter_read_timeout_is_a_total() @test
{
	if (!loopback::pki_ready()) return;
	Rig r;
	r.open(loopback::client_cfg());
	defer r.close();
	// 300 bytes from the server, handed over one byte per read and slowly: each wait is short, the sum is not
	char[300] data;
	data[..] = 'z';
	r.end.server.write(&data)!!;
	r.end.collect();
	r.end.read_limit = 1;
	r.end.read_delay_ms = 5;
	char[512] buf;
	assert(@catch(r.t.read(&buf, 50 * time::MS)) == tls::TIMEOUT);
	// what arrived stays in the engine: with time to spare the same read finishes the record
	usz total = 0;
	while (total < 300)
	{
		total += r.t.read(buf[total..], 10 * time::SEC)!!;
	}
	assert(total == 300);
	assert(buf[0] == 'z' && buf[299] == 'z');
}
