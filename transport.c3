// Transport shape shared (by shape, not by import) with mqtt.c3l, modbus.c3l, s7.c3l and opcua.c3l: every library
// declares this interface and its own TIMEOUT/CLOSED faults in its own module, so any implementor can be passed to any
// library through an explicit interface cast.
module tls;
import std::collections::list, std::time;

interface Transport
{
	// Waits at most `timeout` (DURATION_ZERO = no limit) for data; returns 1..buf.len bytes.
	// Faults: TIMEOUT (nothing arrived in time), CLOSED (peer EOF, or after close()). Never returns 0 for a non-empty buf;
	// an empty buf returns 0 without a syscall.
	fn usz? read(char[] buf, Duration timeout);
	// Writes ALL of data or faults (TIMEOUT, CLOSED). `timeout` bounds each wait for writability. Empty data: no-op.
	// A fault may leave part of data sent, so a plain transport can usually try again; a TlsTransport cannot (its
	// stream would have a gap) and stays failed: after a write fault, reconnect.
	fn void? write(char[] data, Duration timeout);
	// Idempotent. Releases the OS handle (a TlsTransport sends close_notify first).
	fn void? close();
}

// In-memory loopback pair for peer-free tests: bytes written to one end are read from the other.
// A read on an empty open pipe returns TIMEOUT immediately (test doubles never block).
// Both ends must stay at the same address until free() is called on each.
struct MemTransport (Transport)
{
	List{char} inbox;
	usz read_pos;
	MemTransport* peer;
	bool closed;
}

fn void mem_pair(MemTransport* a, MemTransport* b, Allocator allocator)
{
	*a = { .peer = b };
	*b = { .peer = a };
	a.inbox.init(allocator);
	b.inbox.init(allocator);
}

fn void MemTransport.free(&self)
{
	// the other end must not keep writing into freed storage: it sees a closed peer
	if (self.peer && self.peer.peer == self) self.peer.peer = null;
	self.inbox.free();
	*self = {};
}

fn usz? MemTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (buf.len == 0) return 0;
	usz avail = (usz)self.inbox.len() - self.read_pos;
	if (avail == 0)
	{
		self.inbox.clear();
		self.read_pos = 0;
		// the peer has closed (or was freed): everything is drained, so this is end of stream
		if (self.peer == null || self.peer.closed) return CLOSED~;
		return TIMEOUT~;
	}
	usz n = avail < buf.len ? avail : buf.len;
	buf[:n][..] = self.inbox.array_view()[self.read_pos:n][..];
	self.read_pos += n;
	if (self.read_pos == (usz)self.inbox.len())
	{
		// fully consumed: start over so a steady stream does not grow the buffer without bound
		self.inbox.clear();
		self.read_pos = 0;
	}
	return n;
}

fn void? MemTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (data.len == 0) return;
	if (self.peer == null || self.peer.closed) return CLOSED~;
	self.peer.inbox.push_all(data);
}

fn void? MemTransport.close(&self) @dynamic
{
	self.closed = true;
}
