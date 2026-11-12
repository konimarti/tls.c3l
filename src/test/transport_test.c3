module tls::transport_test;

import tls;
import std::io, std::net, std::net::tcp, std::time, std::thread;

// Two connected TcpTransports on the loopback interface (client, accepted).
struct TcpPair
{
	TcpServerSocket server;
	TcpTransport client;
	TcpTransport accepted;
}

fn void TcpPair.open(&self)
{
	self.server = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	ushort port = self.server.local_port()!!;
	self.client = tls::tcp_connect("127.0.0.1", port, 5 * time::SEC)!!;
	self.accepted = tls::tcp_wrap(tcp::accept(&self.server)!!);
}

fn void TcpPair.shut(&self)
{
	(void)self.client.close();
	(void)self.accepted.close();
	(void)self.server.close();
}

fn void test_tcp_conformance() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	tls::check_conformance(&p.client, &p.accepted);
}

fn void test_tcp_conformance_reversed() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	tls::check_conformance(&p.accepted, &p.client);
}

// Writer thread: one write call of the whole buffer.
struct Sender
{
	TcpTransport* t;
	char[] data;
	bool ok;
}

fn int send_all(void* arg)
{
	Sender* s = (Sender*)arg;
	s.ok = @ok(s.t.write(s.data, 10 * time::SEC));
	return 0;
}

fn void test_tcp_one_mebibyte_in_one_write() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	usz size = 1024 * 1024;
	char[] data = mem::new_array(char, (sz)size);
	defer free(data);
	foreach (i, &c : data) *c = (char)(i * 31 + i / 251);

	Sender s = { .t = &p.client, .data = data };
	Thread th;
	th.create(&send_all, &s)!!;

	char[] got = mem::new_array(char, (sz)size);
	defer free(got);
	usz at = 0;
	while (at < size)
	{
		at += p.accepted.read(got[at:min(size - at, (usz)65536)], 10 * time::SEC)!!;
	}
	th.join()!!;
	assert(s.ok);
	assert(got == data);

	// orderly shutdown from the writer side: the reader sees CLOSED
	p.client.close()!!;
	char[8] one;
	assert(@catch(p.accepted.read(&one, 5 * time::SEC)) == tls::CLOSED);
}

fn void test_tcp_read_times_out() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	char[8] buf;
	Clock c = clock::now();
	assert(@catch(p.accepted.read(&buf, 50 * time::MS)) == tls::TIMEOUT);
	// poll cannot return before the timeout; no upper bound is asserted (slow runners)
	assert(c.to_now().to_ms() >= 40);
	// the connection is still usable after a timeout
	p.client.write("a", 2 * time::SEC)!!;
	assert(p.accepted.read(&buf, 2 * time::SEC)!! == 1);
}

fn void test_tcp_use_after_close() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	char[4] buf;
	p.client.close()!!;
	p.client.close()!!;
	assert(@catch(p.client.read(&buf, 10 * time::MS)) == tls::CLOSED);
	assert(@catch(p.client.write("x", 10 * time::MS)) == tls::CLOSED);
	// an empty buffer on a closed transport is still CLOSED, not 0
	assert(@catch(p.client.read(buf[:0], 10 * time::MS)) == tls::CLOSED);
}

fn void test_tcp_connect_refused_is_a_fault() @test
{
	// a port that was just released: nothing listens there
	TcpServerSocket s = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	ushort port = s.local_port()!!;
	(void)s.close();
	TcpTransport? t = tls::tcp_connect("127.0.0.1", port, 2 * time::SEC);
	assert(!@ok(t));
}

fn void test_tcp_write_to_reset_peer_is_closed() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	p.accepted.close()!!;
	// the first sends after the peer went away may still succeed; eventually the transport reports CLOSED
	// and the process survives (no SIGPIPE)
	char[1024] chunk;
	chunk[..] = 'z';
	fault last = {};
	for (int i = 0; i < 200 && !last; i++)
	{
		last = @catch(p.client.write(&chunk, 2 * time::SEC));
	}
	assert(last == tls::CLOSED);
}

fn void test_mem_partial_reads() @test
{
	MemTransport a, b;
	tls::mem_pair(&a, &b, mem);
	defer a.free();
	defer b.free();
	char[10] buf;
	a.write("0123456789", time::DURATION_ZERO)!!;
	assert(b.read(buf[:3], time::DURATION_ZERO)!! == 3);
	assert((String)buf[:3] == "012");
	assert(b.read(&buf, time::DURATION_ZERO)!! == 7);
	assert((String)buf[:7] == "3456789");
	assert(@catch(b.read(&buf, time::DURATION_ZERO)) == tls::TIMEOUT);
}

fn void test_mem_closed_after_drain() @test
{
	MemTransport a, b;
	tls::mem_pair(&a, &b, mem);
	defer a.free();
	defer b.free();
	char[4] buf;
	a.write("ab", time::DURATION_ZERO)!!;
	a.close()!!;
	assert(b.read(&buf, time::DURATION_ZERO)!! == 2);
	assert(@catch(b.read(&buf, time::DURATION_ZERO)) == tls::CLOSED);
	assert(@catch(b.write("x", time::DURATION_ZERO)) == tls::CLOSED);
}

fn void test_mem_free_leaves_the_other_end_closed() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	MemTransport a, b;
	tls::mem_pair(&a, &b, &ta);
	a.write("tail", time::DURATION_ZERO)!!;
	b.write("x", time::DURATION_ZERO)!!;
	a.free();
	char[8] buf;
	// what arrived before the free is still readable, then the end of stream shows
	assert(b.read(&buf, time::DURATION_ZERO)!! == 4);
	assert(@catch(b.read(&buf, time::DURATION_ZERO)) == tls::CLOSED);
	assert(@catch(b.write("data", time::DURATION_ZERO)) == tls::CLOSED);
	b.free();
	assert(!ta.has_leaks());
	assert(ta.allocation_count() == 0);
}

fn void test_mem_inbox_does_not_grow_on_a_steady_stream() @test
{
	MemTransport a, b;
	tls::mem_pair(&a, &b, mem);
	defer a.free();
	defer b.free();
	char[10] buf;
	for (int i = 0; i < 100; i++)
	{
		a.write("0123456789", time::DURATION_ZERO)!!;
		assert(b.read(&buf, time::DURATION_ZERO)!! == 10);
		assert(b.inbox.len() == 0);
		assert(b.read_pos == 0);
	}
}

fn void test_mem_conformance() @test
{
	MemTransport a, b;
	tls::mem_pair(&a, &b, mem);
	defer a.free();
	defer b.free();
	tls::check_conformance(&a, &b);
}

fn void test_mem_no_leaks() @test
{
	TrackingAllocator ta;
	ta.init(mem);
	defer ta.free();
	MemTransport a, b;
	tls::mem_pair(&a, &b, &ta);
	a.write("some bytes", time::DURATION_ZERO)!!;
	b.write("and back", time::DURATION_ZERO)!!;
	a.free();
	b.free();
	assert(!ta.has_leaks());
	assert(ta.allocation_count() == 0);
}

// A second library declares its own, identically shaped interface; a TcpTransport crosses over by explicit cast.
interface OtherTransport
{
	fn usz? read(char[] buf, Duration timeout);
	fn void? write(char[] data, Duration timeout);
	fn void? close();
}

fn bool other_is_timeout(OtherTransport t)
{
	char[4] buf;
	fault f = @catch(t.read(&buf, 20 * time::MS));
	// faults belong to the implementing module: match by name, never by identity with a local TIMEOUT
	return f.description.ends_with("::TIMEOUT");
}

fn void test_cast_to_other_interface() @test
{
	TcpPair p;
	p.open();
	defer p.shut();
	Transport mine = &p.accepted;
	OtherTransport theirs = (OtherTransport)mine;
	assert(other_is_timeout(theirs));
	OtherTransport direct = (OtherTransport)&p.accepted;
	assert(other_is_timeout(direct));
	// the fault is the implementing library's own
	char[4] buf;
	assert(@catch(theirs.read(&buf, 20 * time::MS)) == tls::TIMEOUT);
	p.client.write("q", 2 * time::SEC)!!;
	assert(theirs.read(&buf, 2 * time::SEC)!! == 1);
}
