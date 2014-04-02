/* hmac-sha512.c - optimized hmac-sha512 implementation
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */ 

#include <string.h>
#include <stdint.h>
#include "sha512.h"

void pf_hmac_sha512 (const unsigned char *key, size_t keylen, const unsigned char *in,  size_t len, uint64_t digest[8])
{
	int i;
	unsigned char ipad[128];
	unsigned char opad[128];
	unsigned char buf[ 128] = {0};

	uint64_t tmp1 = 0, tmp2 = 0;

	uint64_t a,  b,  c,  d,  e,  f,  g,  h,
		 aa, bb, cc, dd, ee, ff, gg, hh,
		 o0, o1, o2, o3, o4, o5, o6, o7;

	uint64_t w0  = 0, w1  = 0, w2  = 0, w3  = 0,
		 w4  = 0, w5  = 0, w6  = 0, w7  = 0,
		 w8  = 0, w9  = 0, w10 = 0, w11 = 0,
		 w12 = 0, w13 = 0, w14 = 0, w15 = 0;

	memset (ipad, 0x36, 128);
	memset (opad, 0x5c, 128);

	for (i = 0; i < keylen && i < MAXKEY; i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	uchar_to_uint64 ( w0, ipad,  0 << 3);
	uchar_to_uint64 ( w1, ipad,  1 << 3);
	uchar_to_uint64 ( w2, ipad,  2 << 3);
	uchar_to_uint64 ( w3, ipad,  3 << 3);
	uchar_to_uint64 ( w4, ipad,  4 << 3);
	uchar_to_uint64 ( w5, ipad,  5 << 3);
	uchar_to_uint64 ( w6, ipad,  6 << 3);
	uchar_to_uint64 ( w7, ipad,  7 << 3);
	uchar_to_uint64 ( w8, ipad,  8 << 3);
	uchar_to_uint64 ( w9, ipad,  9 << 3);
	uchar_to_uint64 (w10, ipad, 10 << 3);
	uchar_to_uint64 (w11, ipad, 11 << 3);
	uchar_to_uint64 (w12, ipad, 12 << 3);
	uchar_to_uint64 (w13, ipad, 13 << 3);
	uchar_to_uint64 (w14, ipad, 14 << 3);
	uchar_to_uint64 (w15, ipad, 15 << 3);

	aa = 0x6a09e667f3bcc908;
	bb = 0xbb67ae8584caa73b;
	cc = 0x3c6ef372fe94f82b;
	dd = 0xa54ff53a5f1d36f1;
	ee = 0x510e527fade682d1;
	ff = 0x9b05688c2b3e6c1f;
	gg = 0x1f83d9abfb41bd6b;
	hh = 0x5be0cd19137e2179;

	SHA512_BODY;

	for (i = 0; i < len; i++)
		buf[i] = in[i];
	buf[len] = 0x80;

	uchar_to_uint64 ( w0, buf,  0 << 3);
	uchar_to_uint64 ( w1, buf,  1 << 3);
	uchar_to_uint64 ( w2, buf,  2 << 3);
	uchar_to_uint64 ( w3, buf,  3 << 3);
	uchar_to_uint64 ( w4, buf,  4 << 3);
	uchar_to_uint64 ( w5, buf,  5 << 3);
	uchar_to_uint64 ( w6, buf,  6 << 3);
	uchar_to_uint64 ( w7, buf,  7 << 3);
	uchar_to_uint64 ( w8, buf,  8 << 3);
	uchar_to_uint64 ( w9, buf,  9 << 3);
	uchar_to_uint64 (w10, buf, 10 << 3);
	uchar_to_uint64 (w11, buf, 11 << 3);
	uchar_to_uint64 (w12, buf, 12 << 3);
	uchar_to_uint64 (w13, buf, 13 << 3);
	uchar_to_uint64 (w14, buf, 14 << 3);
	w15 = (len + 128) << 3;

	SHA512_BODY;

	o0 = aa;
	o1 = bb;
	o2 = cc;
	o3 = dd;
	o4 = ee;
	o5 = ff;
	o6 = gg;
	o7 = hh;

	uchar_to_uint64 ( w0, opad,  0 << 3);
	uchar_to_uint64 ( w1, opad,  1 << 3);
	uchar_to_uint64 ( w2, opad,  2 << 3);
	uchar_to_uint64 ( w3, opad,  3 << 3);
	uchar_to_uint64 ( w4, opad,  4 << 3);
	uchar_to_uint64 ( w5, opad,  5 << 3);
	uchar_to_uint64 ( w6, opad,  6 << 3);
	uchar_to_uint64 ( w7, opad,  7 << 3);
	uchar_to_uint64 ( w8, opad,  8 << 3);
	uchar_to_uint64 ( w9, opad,  9 << 3);
	uchar_to_uint64 (w10, opad, 10 << 3);
	uchar_to_uint64 (w11, opad, 11 << 3);
	uchar_to_uint64 (w12, opad, 12 << 3);
	uchar_to_uint64 (w13, opad, 13 << 3);
	uchar_to_uint64 (w14, opad, 14 << 3);
	uchar_to_uint64 (w15, opad, 15 << 3);

	aa = 0x6a09e667f3bcc908;
	bb = 0xbb67ae8584caa73b;
	cc = 0x3c6ef372fe94f82b;
	dd = 0xa54ff53a5f1d36f1;
	ee = 0x510e527fade682d1;
	ff = 0x9b05688c2b3e6c1f;
	gg = 0x1f83d9abfb41bd6b;
	hh = 0x5be0cd19137e2179;

	SHA512_BODY;

	w0 = o0;
	w1 = o1;
	w2 = o2;
	w3 = o3;
	w4 = o4;
	w5 = o5;
	w6 = o6;
	w7 = o7;
	w8  = 0x8000000000000000;
	w9  = 0;
	w10 = 0;
	w11 = 0;
	w12 = 0;
	w13 = 0;
	w14 = 0;
	w15 = (64 + 128) << 3;

	SHA512_BODY;

	digest[0] = __builtin_bswap64 (aa);
	digest[1] = __builtin_bswap64 (bb);
	digest[2] = __builtin_bswap64 (cc);
	digest[3] = __builtin_bswap64 (dd);
	digest[4] = __builtin_bswap64 (ee);
	digest[5] = __builtin_bswap64 (ff);
	digest[6] = __builtin_bswap64 (gg);
	digest[7] = __builtin_bswap64 (hh);
}
