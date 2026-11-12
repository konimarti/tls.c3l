module tls::error_test;

import tls;

fn void test_transport_faults_are_distinct() @test
{
	fault a = tls::TIMEOUT;
	fault b = tls::CLOSED;
	fault c = tls::TRUNCATED;
	assert(a != b);
	assert(a != c);
	assert(b != c);
	assert(a == tls::TIMEOUT);
}
