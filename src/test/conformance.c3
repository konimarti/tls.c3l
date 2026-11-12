module tls;
import std::time;

// The contract every Transport implementation must satisfy. `a` and `b` are the two ends of one connection.
// Other libraries copy this function for their own transports.
fn void check_conformance(Transport a, Transport b)
{
	char[16] buf;

	// data arrives; reads are partial and never return 0 for a non-empty buffer
	a.write("hello", 2 * time::SEC)!!;
	usz total = 0;
	while (total < 5)
	{
		usz want = total == 0 ? 3 : 8;
		usz n = b.read(buf[total:want > 5 - total ? 5 - total : want], 2 * time::SEC)!!;
		assert(n >= 1);
		total += n;
	}
	assert((String)buf[:5] == "hello");

	// empty buffers: no syscall, no fault
	assert(b.read(buf[:0], time::DURATION_ZERO)!! == 0);
	a.write("", time::DURATION_ZERO)!!;

	// nothing to read: TIMEOUT
	assert(@catch(b.read(buf[..], 30 * time::MS)) == TIMEOUT);

	// data written before close is still delivered, then end of stream is CLOSED
	a.write("x", 2 * time::SEC)!!;
	a.close()!!;
	a.close()!!;                                   // idempotent
	assert(@catch(a.read(buf[..], 30 * time::MS)) == CLOSED);
	assert(@catch(a.write("y", 30 * time::MS)) == CLOSED);
	assert(b.read(buf[..], 2 * time::SEC)!! == 1);
	assert(buf[0] == 'x');
	assert(@catch(b.read(buf[..], 2 * time::SEC)) == CLOSED);
	assert(@catch(b.read(buf[..], 2 * time::SEC)) == CLOSED);   // stays closed

	b.close()!!;
	b.close()!!;
	assert(@catch(b.read(buf[..], 30 * time::MS)) == CLOSED);
	assert(@catch(b.write("z", 30 * time::MS)) == CLOSED);
}
