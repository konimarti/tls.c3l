module tls::version_test;

import tls;

fn void test_version_matches_project_json() @test
{
	// in the library's own test build the library is the top-level project, so PROJECT_VERSION is its version
	assert(tls::VERSION == env::PROJECT_VERSION);
}
