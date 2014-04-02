/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

/*
 * This file implements some internal consistency checks. These tests
 * are meant to complement, not replace, the known-answer tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "makwa.h"

static const unsigned char PUB2048[] = {
	0x55, 0x41, 0x4d, 0x30, 0x01, 0x00, 0xc2, 0x2c,
	0x40, 0xbb, 0xd0, 0x56, 0xbb, 0x21, 0x3a, 0xad,
	0x7c, 0x83, 0x05, 0x19, 0x10, 0x1a, 0xb9, 0x26,
	0xae, 0x18, 0xe3, 0xe9, 0xfc, 0x96, 0x99, 0xc8,
	0x06, 0xe0, 0xae, 0x5c, 0x25, 0x94, 0x14, 0xa0,
	0x1a, 0xc1, 0xd5, 0x2e, 0x87, 0x3e, 0xc0, 0x80,
	0x46, 0xa6, 0x8e, 0x34, 0x4c, 0x8d, 0x74, 0xa5,
	0x08, 0x95, 0x28, 0x42, 0xef, 0x0f, 0x03, 0xf7,
	0x1a, 0x6e, 0xdc, 0x07, 0x7f, 0xaa, 0x14, 0x89,
	0x9a, 0x79, 0xf8, 0x3c, 0x3a, 0xe1, 0x36, 0xf7,
	0x74, 0xfa, 0x6e, 0xb8, 0x8f, 0x1d, 0x1a, 0xea,
	0x5e, 0xa0, 0x2f, 0xc0, 0xcc, 0xaf, 0x96, 0xe2,
	0xce, 0x86, 0xf3, 0x49, 0x0f, 0x49, 0x93, 0xb4,
	0xb5, 0x66, 0xc0, 0x07, 0x96, 0x41, 0x47, 0x2d,
	0xef, 0xc1, 0x4b, 0xec, 0xcf, 0x48, 0x98, 0x4a,
	0x79, 0x46, 0xf1, 0x44, 0x1e, 0xa1, 0x44, 0xea,
	0x4c, 0x80, 0x2a, 0x45, 0x75, 0x50, 0xba, 0x3d,
	0xf0, 0xf1, 0x4c, 0x09, 0x0a, 0x75, 0xfe, 0x9e,
	0x6a, 0x77, 0xcf, 0x0b, 0xe9, 0x8b, 0x71, 0xd5,
	0x62, 0x51, 0xa8, 0x69, 0x43, 0xe7, 0x19, 0xd2,
	0x78, 0x65, 0xa4, 0x89, 0x56, 0x6c, 0x1d, 0xc5,
	0x7f, 0xcd, 0xef, 0xac, 0xa6, 0xab, 0x04, 0x3f,
	0x8e, 0x13, 0xf6, 0xc0, 0xbe, 0x7b, 0x39, 0xc9,
	0x2d, 0xa8, 0x6e, 0x1d, 0x87, 0x47, 0x7a, 0x18,
	0x9e, 0x73, 0xce, 0x8e, 0x31, 0x1d, 0x3d, 0x51,
	0x36, 0x1f, 0x8b, 0x00, 0x24, 0x9f, 0xb3, 0xd8,
	0x43, 0x56, 0x07, 0xb1, 0x4a, 0x1e, 0x70, 0x17,
	0x0f, 0x9a, 0xf3, 0x67, 0x84, 0x11, 0x0a, 0x3f,
	0x2e, 0x67, 0x42, 0x8f, 0xc1, 0x8f, 0xb0, 0x13,
	0xb3, 0x0f, 0xe6, 0x78, 0x2a, 0xec, 0xb4, 0x42,
	0x8d, 0x7c, 0x8e, 0x35, 0x4a, 0x0f, 0xbd, 0x06,
	0x1b, 0x01, 0x91, 0x7c, 0x72, 0x7a, 0xbe, 0xe0,
	0xfe, 0x3f, 0xd3, 0xce, 0xf7, 0x61
};

static const unsigned char PRIV2048[] = {
	0x55, 0x41, 0x4d, 0x31, 0x00, 0x80, 0xea, 0x43,
	0xd7, 0x9d, 0xf0, 0xb8, 0x74, 0x14, 0x0a, 0x55,
	0xec, 0xd1, 0x44, 0x73, 0x2e, 0xaf, 0x49, 0xd9,
	0xc8, 0xf0, 0xe4, 0x37, 0x6f, 0x5d, 0x72, 0x97,
	0x2a, 0x14, 0x66, 0x79, 0xe3, 0x82, 0x44, 0xf5,
	0xa9, 0x6e, 0xf5, 0xce, 0x92, 0x8a, 0x54, 0x25,
	0x12, 0x40, 0x47, 0x5f, 0xd1, 0xdd, 0x96, 0x8b,
	0x9a, 0x77, 0xad, 0xd1, 0x65, 0x50, 0x56, 0x4c,
	0x1d, 0xd2, 0x42, 0x40, 0x08, 0xea, 0x83, 0xc2,
	0x59, 0xd5, 0x3b, 0x88, 0x61, 0xc5, 0xe9, 0x4f,
	0x22, 0x8f, 0x03, 0xc4, 0x98, 0xdd, 0x3c, 0x8c,
	0x69, 0x49, 0xe3, 0x66, 0x02, 0xfe, 0x74, 0x6d,
	0x64, 0xd5, 0x14, 0x89, 0xc7, 0x6c, 0x74, 0xdb,
	0xc2, 0x44, 0x7e, 0x22, 0x2e, 0xcf, 0x28, 0xfa,
	0x9b, 0xd4, 0x4e, 0x81, 0x41, 0x07, 0x55, 0x87,
	0x9e, 0x71, 0xbd, 0xf8, 0xfb, 0x4a, 0x61, 0xd8,
	0xad, 0x3d, 0xf4, 0x4f, 0xfc, 0x9b, 0x00, 0x80,
	0xd4, 0x30, 0x28, 0xee, 0x37, 0x4f, 0xeb, 0xb9,
	0x3b, 0x5d, 0xf8, 0xdc, 0x1c, 0x68, 0x37, 0x13,
	0xab, 0x05, 0x10, 0xaf, 0x7e, 0xeb, 0xe6, 0x3d,
	0x33, 0xf9, 0x0a, 0xf7, 0x63, 0xfa, 0x22, 0x64,
	0xb6, 0x8b, 0x09, 0x21, 0x94, 0x90, 0xa5, 0xa5,
	0x64, 0x4d, 0x63, 0x56, 0x85, 0x9c, 0x27, 0xcd,
	0xf9, 0x76, 0x71, 0x12, 0x2e, 0x4d, 0x9a, 0x13,
	0xd9, 0x16, 0x09, 0x60, 0x9c, 0x46, 0x90, 0x14,
	0xda, 0xe3, 0x0f, 0x9a, 0xe6, 0xbc, 0x93, 0x78,
	0xe7, 0x97, 0x47, 0x60, 0x1e, 0xee, 0xa8, 0x18,
	0x46, 0x98, 0x42, 0x72, 0x08, 0x9c, 0x08, 0x53,
	0x49, 0x7f, 0xc5, 0x3a, 0x51, 0xd4, 0x5d, 0x37,
	0xf0, 0xcb, 0x4e, 0x67, 0xd8, 0xb9, 0x59, 0x21,
	0xb7, 0xd2, 0x93, 0xd7, 0x55, 0xb4, 0x9d, 0xda,
	0x55, 0xb8, 0x15, 0x29, 0xa7, 0x06, 0xcd, 0x67,
	0xee, 0x3b, 0xfe, 0xfe, 0xc4, 0xf3, 0xf5, 0xb3
};

#define FAIL   do { \
		fprintf(stderr, \
			"FAIL: self-test failed, line %ld\n", (long)__LINE__); \
		abort(); \
	} while (0)

#define CHECK(x)   do { \
		if (!(x)) { \
			FAIL; \
		} \
	} while (0)

#define CE(x, expected)   do { \
		int error_code = (x); \
		if (error_code != (expected)) { \
			fprintf(stderr, "FAIL (line %ld): %s returned %d\n", \
				(long)__LINE__, #x, error_code); \
			abort(); \
		} \
	} while (0)

#define CC(x)   CE(x, MAKWA_OK)

#define CZ(x)   do { \
		if ((x) == 0) { \
			fprintf(stderr, "FAIL (line %ld): %s returned zero\n", \
				(long)__LINE__, #x); \
			abort(); \
		} \
	} while (0)

static void *
xmalloc(size_t len)
{
	void *x;

	if (len == 0) {
		return NULL;
	}
	x = malloc(len);
	if (x == NULL) {
		fprintf(stderr, "memory allocation failed (%lu bytes)\n",
			(unsigned long )len);
		abort();
	}
	return x;
}

static void
xfree(void *x)
{
	if (x != NULL) {
		free(x);
	}
}

static void
check_simple(int pre_hash, size_t post_hash_length, unsigned long work_factor)
{
	makwa_context *mpub, *mpriv;
	char h1[1024], *h2;
	size_t h1_len, h2_len;

	CZ(mpub = makwa_new());
	CZ(mpriv = makwa_new());
	CC(makwa_init_full(mpub, PUB2048, sizeof PUB2048, MAKWA_SHA256,
		pre_hash, post_hash_length, work_factor));
	CC(makwa_init_full(mpriv, PRIV2048, sizeof PRIV2048, MAKWA_SHA256,
		pre_hash, post_hash_length, work_factor));

	/*
	 * With mpub, we use the "pre-allocated large buffer" pattern.
	 */
	h1_len = sizeof h1;
	CC(makwa_simple_hash_new(mpub, "test1", h1, &h1_len));
	CHECK(h1_len == 1 + strlen(h1));
	CC(makwa_simple_hash_verify(mpub, "test1", h1));
	CC(makwa_simple_hash_verify(mpriv, "test1", h1));
	CE(makwa_simple_hash_verify(mpub, "test2", h1), MAKWA_WRONG_PASSWORD);
	CE(makwa_simple_hash_verify(mpriv, "test2", h1), MAKWA_WRONG_PASSWORD);

	/*
	 * With mpriv, we use the "allocate on demand" pattern. Since we
	 * hash the same string, and the internal salt always has length
	 * 16 bytes, we should obtain the same string length than
	 * previously.
	 */
	CC(makwa_simple_hash_new(mpriv, "test1", NULL, &h2_len));
	CHECK(h2_len == h1_len);
	h2 = xmalloc(h2_len);
	CC(makwa_simple_hash_new(mpriv, "test1", h2, &h2_len));
	CHECK(h2_len == h1_len && h2_len == 1 + strlen(h2));
	CC(makwa_simple_hash_verify(mpub, "test1", h2));
	CC(makwa_simple_hash_verify(mpriv, "test1", h2));
	CE(makwa_simple_hash_verify(mpub, "test2", h2), MAKWA_WRONG_PASSWORD);
	CE(makwa_simple_hash_verify(mpriv, "test2", h2), MAKWA_WRONG_PASSWORD);

	/*
	 * Since each call to makwa_simple_hash_new() generates a new
	 * salt, the strings h1 and h2 ought to be distinct, with very
	 * high probability.
	 */
	CHECK(strcmp(h1, h2) != 0);

	free(h2);
	makwa_free(mpub);
	makwa_free(mpriv);
}

static void
check_work_factor_change()
{
	makwa_context *mpub_small, *mpriv_small;
	makwa_context *mpub_large, *mpriv_large;

	char hs[1024], hl[1024]; 

	CZ(mpub_small = makwa_new());
	CZ(mpriv_small = makwa_new());
	CZ(mpub_large = makwa_new());
	CZ(mpriv_large = makwa_new());
	CC(makwa_init_full(mpub_small, PUB2048, sizeof PUB2048,
		MAKWA_SHA256, 0, 0, 384));
	CC(makwa_init_full(mpriv_small, PRIV2048, sizeof PRIV2048,
		MAKWA_SHA256, 0, 0, 384));
	CC(makwa_init_full(mpub_large, PUB2048, sizeof PUB2048,
		MAKWA_SHA256, 0, 0, 4096));
	CC(makwa_init_full(mpriv_large, PRIV2048, sizeof PRIV2048,
		MAKWA_SHA256, 0, 0, 4096));

	CC(makwa_simple_hash_new(mpub_small, "test1", hs, NULL));
	strcpy(hl, hs);
	CC(makwa_simple_reset_work_factor(mpub_small, hl, 4096));
	CC(makwa_simple_hash_verify(mpriv_large, "test1", hl));
	strcpy(hl, hs);
	CC(makwa_simple_reset_work_factor(mpriv_small, hl, 4096));
	CC(makwa_simple_hash_verify(mpub_large, "test1", hl));
	strcpy(hs, hl);
	CC(makwa_simple_reset_work_factor(mpriv_large, hl, 384));
	CC(makwa_simple_hash_verify(mpub_small, "test1", hl));

	makwa_free(mpub_small);
	makwa_free(mpub_large);
	makwa_free(mpriv_small);
	makwa_free(mpriv_large);
}

static void
check_unescrow()
{
	makwa_context *mpub, *mpriv;
	char h[1024];

	CZ(mpub = makwa_new());
	CZ(mpriv = makwa_new());
	CC(makwa_init_full(mpub, PUB2048, sizeof PUB2048, MAKWA_SHA256,
		0, 0, 3072));
	CC(makwa_init_full(mpriv, PRIV2048, sizeof PRIV2048, MAKWA_SHA256,
		0, 0, 3072));
	CC(makwa_simple_hash_new(mpub, "test1", h, NULL));
	CC(makwa_simple_unescrow(mpriv, h));
	CHECK(strcmp(h, "test1") == 0);
	makwa_free(mpub);
	makwa_free(mpriv);
}

static void
check_delegation()
{
	void *param, *req, *ans, *str_out;
	size_t param_len, req_len, ans_len, str_out_len;
	makwa_context *mpub, *mpriv;
	makwa_delegation_parameters *mdp;
	makwa_delegation_context *mdc;

	/*
	 * Generate some delegation parameters for work factor 16384. We
	 * use the private key so that generation remains tolerably fast.
	 */
	CC(makwa_delegation_generate(PRIV2048, sizeof PRIV2048,
		16384, NULL, &param_len));
	param = xmalloc(param_len);
	CC(makwa_delegation_generate(PRIV2048, sizeof PRIV2048,
		16384, param, &param_len));
	CZ(mdp = makwa_delegation_new());
	CC(makwa_delegation_init(mdp, param, param_len));

	/*
	 * Create two contexts; we will use the "mpub" context for
	 * delegated hashing, and "mpriv" for non-delegated verification.
	 */
	CZ(mpub = makwa_new());
	CZ(mpriv = makwa_new());
	CC(makwa_init_full(mpub, PUB2048, sizeof PUB2048, MAKWA_SHA256,
		0, 0, 16384));
	CC(makwa_init_full(mpriv, PRIV2048, sizeof PRIV2048, MAKWA_SHA256,
		0, 0, 16384));

	/*
	 * Begin delegated hash, and encode request.
	 */
	CZ(mdc = makwa_delegation_context_new());
	CC(makwa_simple_hash_new_delegate_begin(mpub, mdp, "test1", mdc));
	CC(makwa_delegation_context_encode(mdc, NULL, &req_len));
	req = xmalloc(req_len);
	CC(makwa_delegation_context_encode(mdc, req, &req_len));

	/*
	 * Compute the answer (this part emulates the delegation server).
	 */
	CC(makwa_delegation_answer(req, req_len, NULL, &ans_len));
	ans = xmalloc(ans_len);
	CC(makwa_delegation_answer(req, req_len, ans, &ans_len));

	/*
	 * Finalize the hash value; then verify it with mpriv.
	 */
	CC(makwa_simple_hash_delegate_end(mdc,
		ans, ans_len, NULL, &str_out_len));
	str_out = xmalloc(str_out_len);
	CC(makwa_simple_hash_delegate_end(mdc,
		ans, ans_len, str_out, &str_out_len));

	CC(makwa_simple_hash_verify(mpriv, "test1", str_out));
	xfree(req);
	xfree(ans);

	/*
	 * A new delegated hash, for verification now.
	 */
	CC(makwa_simple_hash_verify_delegate_begin(
		mpub, mdp, "test1", str_out, mdc));
	CC(makwa_delegation_context_encode(mdc, NULL, &req_len));
	req = xmalloc(req_len);
	CC(makwa_delegation_context_encode(mdc, req, &req_len));

	/*
	 * Compute the answer (this part emulates the delegation server).
	 */
	CC(makwa_delegation_answer(req, req_len, NULL, &ans_len));
	ans = xmalloc(ans_len);
	CC(makwa_delegation_answer(req, req_len, ans, &ans_len));

	/*
	 * Finalize the verification process.
	 */
	CC(makwa_simple_hash_verify_delegate_end(mdc, ans, ans_len));

	xfree(req);
	xfree(ans);
	xfree(str_out);
	makwa_free(mpub);
	makwa_free(mpriv);
	makwa_delegation_free(mdp);
	makwa_delegation_context_free(mdc);
	xfree(param);
}

static void
check_PHC(void)
{
	static const unsigned char salt[] = { 0x01, 0x02, 0x03, 0x04 };
	static const char intxt[] = "sample for PHC";
	unsigned char out[16];
	size_t u;

	CC(PHS(out, sizeof out, intxt, strlen(intxt),
		salt, sizeof salt, 8192, 0));
	for (u = 0; u < sizeof out; u ++) {
		printf("%02x", out[u]);
	}
	printf("\n");
}

/*
 * Run a speed test. We want two measures: the number of squarings per
 * second, and the number of private key operations per second. The latter
 * is supposed to be roughly similar to the number of RSA private key
 * operations, on the same machine and with the same modulus size.
 */
static void
speed_test(void)
{
	makwa_context *mc;
	double ttprev;
	long w, wprev, cc;
	char str[1024];

	CZ(mc = makwa_new());
	CC(makwa_init(mc, PUB2048, sizeof PUB2048, 0));
	wprev = 1;
	w = 2;
	ttprev = 0.0;
	for (;;) {
		clock_t begin, end;
		double tt;
		unsigned char out[16];
		unsigned char salt[16];

		begin = clock();
		CC(makwa_make_new_salt(salt, sizeof salt));
		CC(makwa_hash(mc, "speedtest", 9, salt, sizeof salt,
			1, 16, w, out, NULL));
		end = clock();
		tt = (double)(end - begin) / CLOCKS_PER_SEC;
		if (tt > 4.0) {
			printf("wf/s = %.2f\n",
				(double)(w - wprev) / (tt - ttprev));
			break;
		}
		ttprev = tt;
		wprev = w;
		w <<= 1;
	}

	CC(makwa_init_full(mc, PRIV2048, sizeof PRIV2048, 0, 1, 16, 65536));
	CC(makwa_simple_hash_new(mc, "speedtest", str, NULL));
	cc = 2;
	for (;;) {
		clock_t begin, end;
		double tt;
		long m;

		begin = clock();
		for (m = 0; m < cc; m ++) {
			CC(makwa_simple_hash_verify(mc, "speedtest", str));
		}
		end = clock();
		tt = (double)(end - begin) / CLOCKS_PER_SEC;
		if (tt > 4.0) {
			printf("priv/s = %.2f\n", (double)cc / tt);
			break;
		}
		cc <<= 1;
	}

	makwa_free(mc);
}

int
main(void)
{
	printf("Simple API...\n");
	check_simple(0, 0, 384);
	check_simple(0, 12, 384);
	check_simple(1, 0, 384);
	check_simple(1, 12, 384);
	check_simple(0, 0, 4096);
	check_simple(0, 12, 4096);
	check_simple(1, 0, 4096);
	check_simple(1, 12, 4096);

	printf("Work factor change...\n");
	check_work_factor_change();

	printf("Unescrow...\n");
	check_unescrow();

	printf("Delegation...\n");
	check_delegation();

	printf("PHC API...\n");
	check_PHC();

	printf("All tests OK.\n");

	printf("Speed test...\n");
	speed_test();

	return 0;
}
