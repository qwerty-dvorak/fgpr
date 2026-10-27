#define _POSIX_C_SOURCE 200809L
/* These are runtime checks even when xmake selects release mode. */
#undef NDEBUG
#include "ctap.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int verifications;
static int denied(void *arg)
{
	(void)arg;
	verifications++;
	return 0x27;
}

/* CTAP GetAssertion, an RP with no credentials, 32-byte client hash, and
 * options encoded in Firefox's uv-before-up order. Handcrafted bytes avoid
 * a client encoder silently canonicalizing the very regression under test. */
static size_t request(unsigned char *out, const unsigned char *options, size_t n)
{
	static const unsigned char prefix[] = {
		0x02, 0xa3, 0x01, 0x6c,
		'e','x','a','m','p','l','e','.','t','e','s','t',
		0x02, 0x58, 0x20
	};
	size_t i = sizeof(prefix);

	memcpy(out, prefix, i);
	memset(out + i, 0, 32);
	i += 32;
	out[i++] = 0x05;
	memcpy(out + i, options, n);
	return i + n;
}

int main(void)
{
	char dir[] = "/tmp/elanfp-ctap-test.XXXXXX";
	unsigned char in[128], out[4096];
	static const unsigned char firefox[] = {
		0xa2, 0x62, 'u','v', 0xf4, 0x62, 'u','p', 0xf4
	};
	static const unsigned char requires_uv[] = {
		0xa2, 0x62, 'u','v', 0xf5, 0x62, 'u','p', 0xf4
	};
	static const unsigned char duplicate[] = {
		0xa3, 0x62, 'u','p', 0xf4, 0x62, 'u','v', 0xf4,
		0x62, 'u','p', 0xf5
	};
	static const unsigned char malformed[] = { 0x02, 0xa1, 0x01, 0x7a, 0xff, 0xff, 0xff, 0xff };
	struct ctap *c;
	size_t n, r;

	assert(mkdtemp(dir));
	c = ctap_new(dir, denied, NULL);
	assert(c);
	n = request(in, firefox, sizeof(firefox));
	r = ctap_request(c, in, n, out, sizeof(out));
	/* A missing RP credential is not malformed CBOR and never prompts UV. */
	assert(r == 1 && out[0] == 0x2e && verifications == 0);
	n = request(in, requires_uv, sizeof(requires_uv));
	r = ctap_request(c, in, n, out, sizeof(out));
	assert(r == 1 && out[0] == 0x27 && verifications == 1);
	n = request(in, duplicate, sizeof(duplicate));
	r = ctap_request(c, in, n, out, sizeof(out));
	/* Reordering cannot allow conflicting duplicates to bypass UV policy. */
	assert(r == 1 && out[0] == 0x12 && verifications == 1);
	r = ctap_request(c, malformed, sizeof(malformed), out, sizeof(out));
	assert(r == 1 && out[0] == 0x12 && verifications == 1);
	ctap_free(c);
	assert(rmdir(dir) == 0);
	puts("PASS: Firefox option order, UV denial, duplicate rejection and truncated CBOR");
	return 0;
}
