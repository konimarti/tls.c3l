module tls::loopback_support_test;

import tls::loopback;

fn void test_missing_pki_is_skipped_unless_required() @test
{
	assert(loopback::pki_decision(true, false) == RUN);
	assert(loopback::pki_decision(true, true) == RUN);
	assert(loopback::pki_decision(false, false) == SKIP);
	// a CI run that forgot to generate the certificates must fail, not pass quietly
	assert(loopback::pki_decision(false, true) == FAIL);
}
