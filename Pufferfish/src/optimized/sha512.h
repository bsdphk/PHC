/* sha512.h - optimized sha512 implementation.
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "../common/common.h"

#define DIGEST_LEN	64
#define MAXKEY		128

#define uchar_to_uint64(n,b,c)						\
{									\
    (n) = ( (uint64_t) (b)[(c)  ] << 56 )				\
	| ( (uint64_t) (b)[(c)+1] << 48 )				\
	| ( (uint64_t) (b)[(c)+2] << 40 )				\
	| ( (uint64_t) (b)[(c)+3] << 32 )				\
	| ( (uint64_t) (b)[(c)+4] << 24 )				\
	| ( (uint64_t) (b)[(c)+5] << 16 )				\
	| ( (uint64_t) (b)[(c)+6] <<  8 )				\
	| ( (uint64_t) (b)[(c)+7]       );				\
}

#define S0(x) (rotr64(x,28) ^ rotr64(x,34) ^ rotr64(x,39))
#define S1(x) (rotr64(x,14) ^ rotr64(x,18) ^ rotr64(x,41))
#define s0(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ shr(x, 7)   )
#define s1(x) (rotr64(x,19) ^ rotr64(x,61) ^ shr(x, 6)   )

#define Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Maj(x,y,z) ((x & y) | (z & (x | y)))

#define SHA2_STEP(a,b,c,d,e,f,g,h,x,K)					\
{									\
    tmp1 = h + S1(e) + Ch(e,f,g) + K + x;				\
    tmp2 = S0(a) + Maj(a,b,c);						\
    h  = tmp1 + tmp2;							\
    d += tmp1;								\
}

#define SHA512_BODY							\
	a = aa;								\
	b = bb;								\
	c = cc;								\
	d = dd;								\
	e = ee;								\
	f = ff;								\
	g = gg;								\
	h = hh;								\
									\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w0, 0x428a2f98d728ae22);	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w1, 0x7137449123ef65cd);	\
	SHA2_STEP(g, h, a, b, c, d, e, f,  w2, 0xb5c0fbcfec4d3b2f);	\
	SHA2_STEP(f, g, h, a, b, c, d, e,  w3, 0xe9b5dba58189dbbc);	\
	SHA2_STEP(e, f, g, h, a, b, c, d,  w4, 0x3956c25bf348b538);	\
	SHA2_STEP(d, e, f, g, h, a, b, c,  w5, 0x59f111f1b605d019);	\
	SHA2_STEP(c, d, e, f, g, h, a, b,  w6, 0x923f82a4af194f9b);	\
	SHA2_STEP(b, c, d, e, f, g, h, a,  w7, 0xab1c5ed5da6d8118);	\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w8, 0xd807aa98a3030242);	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w9, 0x12835b0145706fbe);	\
	SHA2_STEP(g, h, a, b, c, d, e, f, w10, 0x243185be4ee4b28c);	\
	SHA2_STEP(f, g, h, a, b, c, d, e, w11, 0x550c7dc3d5ffb4e2);	\
	SHA2_STEP(e, f, g, h, a, b, c, d, w12, 0x72be5d74f27b896f);	\
	SHA2_STEP(d, e, f, g, h, a, b, c, w13, 0x80deb1fe3b1696b1);	\
	SHA2_STEP(c, d, e, f, g, h, a, b, w14, 0x9bdc06a725c71235);	\
	SHA2_STEP(b, c, d, e, f, g, h, a, w15, 0xc19bf174cf692694);	\
									\
	w0 = s1(w14) + w9 + s0(w1) + w0;				\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w0, 0xe49b69c19ef14ad2);	\
	w1 = s1(w15) + w10 + s0(w2) + w1;			  	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w1, 0xefbe4786384f25e3);	\
	w2 = s1(w0) + w11 + s0(w3) + w2;				\
	SHA2_STEP(g, h, a, b, c, d, e, f,  w2, 0x0fc19dc68b8cd5b5);	\
	w3 = s1(w1) + w12 + s0(w4) + w3;				\
	SHA2_STEP(f, g, h, a, b, c, d, e,  w3, 0x240ca1cc77ac9c65);	\
	w4 = s1(w2) + w13 + s0(w5) + w4;				\
	SHA2_STEP(e, f, g, h, a, b, c, d,  w4, 0x2de92c6f592b0275);	\
	w5 = s1(w3) + w14 + s0(w6) + w5;				\
	SHA2_STEP(d, e, f, g, h, a, b, c,  w5, 0x4a7484aa6ea6e483);	\
	w6 = s1(w4) + w15 + s0(w7) + w6;				\
	SHA2_STEP(c, d, e, f, g, h, a, b,  w6, 0x5cb0a9dcbd41fbd4);	\
	w7 = s1(w5) + w0 + s0(w8) + w7;					\
	SHA2_STEP(b, c, d, e, f, g, h, a,  w7, 0x76f988da831153b5);	\
	w8 = s1(w6) + w1 + s0(w9) + w8;					\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w8, 0x983e5152ee66dfab);	\
	w9 = s1(w7) + w2 + s0(w10) + w9;				\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w9, 0xa831c66d2db43210);	\
	w10 = s1(w8) + w3 + s0(w11) + w10;			 	\
	SHA2_STEP(g, h, a, b, c, d, e, f, w10, 0xb00327c898fb213f);	\
	w11 = s1(w9) + w4 + s0(w12) + w11;			 	\
	SHA2_STEP(f, g, h, a, b, c, d, e, w11, 0xbf597fc7beef0ee4);	\
	w12 = s1(w10) + w5 + s0(w13) + w12;				\
	SHA2_STEP(e, f, g, h, a, b, c, d, w12, 0xc6e00bf33da88fc2);	\
	w13 = s1(w11) + w6 + s0(w14) + w13;				\
	SHA2_STEP(d, e, f, g, h, a, b, c, w13, 0xd5a79147930aa725);	\
	w14 = s1(w12) + w7 + s0(w15) + w14;				\
	SHA2_STEP(c, d, e, f, g, h, a, b, w14, 0x06ca6351e003826f);	\
	w15 = s1(w13) + w8 + s0(w0) + w15;			 	\
	SHA2_STEP(b, c, d, e, f, g, h, a, w15, 0x142929670a0e6e70);	\
									\
	w0 = s1(w14) + w9 + s0(w1) + w0;				\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w0, 0x27b70a8546d22ffc);	\
	w1 = s1(w15) + w10 + s0(w2) + w1;			  	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w1, 0x2e1b21385c26c926);	\
	w2 = s1(w0) + w11 + s0(w3) + w2;				\
	SHA2_STEP(g, h, a, b, c, d, e, f,  w2, 0x4d2c6dfc5ac42aed);	\
	w3 = s1(w1) + w12 + s0(w4) + w3;				\
	SHA2_STEP(f, g, h, a, b, c, d, e,  w3, 0x53380d139d95b3df);	\
	w4 = s1(w2) + w13 + s0(w5) + w4;				\
	SHA2_STEP(e, f, g, h, a, b, c, d,  w4, 0x650a73548baf63de);	\
	w5 = s1(w3) + w14 + s0(w6) + w5;				\
	SHA2_STEP(d, e, f, g, h, a, b, c,  w5, 0x766a0abb3c77b2a8);	\
	w6 = s1(w4) + w15 + s0(w7) + w6;				\
	SHA2_STEP(c, d, e, f, g, h, a, b,  w6, 0x81c2c92e47edaee6);	\
	w7 = s1(w5) + w0 + s0(w8) + w7;					\
	SHA2_STEP(b, c, d, e, f, g, h, a,  w7, 0x92722c851482353b);	\
	w8 = s1(w6) + w1 + s0(w9) + w8;					\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w8, 0xa2bfe8a14cf10364);	\
	w9 = s1(w7) + w2 + s0(w10) + w9;				\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w9, 0xa81a664bbc423001);	\
	w10 = s1(w8) + w3 + s0(w11) + w10;			 	\
	SHA2_STEP(g, h, a, b, c, d, e, f, w10, 0xc24b8b70d0f89791);	\
	w11 = s1(w9) + w4 + s0(w12) + w11;			 	\
	SHA2_STEP(f, g, h, a, b, c, d, e, w11, 0xc76c51a30654be30);	\
	w12 = s1(w10) + w5 + s0(w13) + w12;				\
	SHA2_STEP(e, f, g, h, a, b, c, d, w12, 0xd192e819d6ef5218);	\
	w13 = s1(w11) + w6 + s0(w14) + w13;				\
	SHA2_STEP(d, e, f, g, h, a, b, c, w13, 0xd69906245565a910);	\
	w14 = s1(w12) + w7 + s0(w15) + w14;				\
	SHA2_STEP(c, d, e, f, g, h, a, b, w14, 0xf40e35855771202a);	\
	w15 = s1(w13) + w8 + s0(w0) + w15;			 	\
	SHA2_STEP(b, c, d, e, f, g, h, a, w15, 0x106aa07032bbd1b8);	\
									\
	w0 = s1(w14) + w9 + s0(w1) + w0;				\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w0, 0x19a4c116b8d2d0c8);	\
	w1 = s1(w15) + w10 + s0(w2) + w1;			  	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w1, 0x1e376c085141ab53);	\
	w2 = s1(w0) + w11 + s0(w3) + w2;				\
	SHA2_STEP(g, h, a, b, c, d, e, f,  w2, 0x2748774cdf8eeb99);	\
	w3 = s1(w1) + w12 + s0(w4) + w3;				\
	SHA2_STEP(f, g, h, a, b, c, d, e,  w3, 0x34b0bcb5e19b48a8);	\
	w4 = s1(w2) + w13 + s0(w5) + w4;				\
	SHA2_STEP(e, f, g, h, a, b, c, d,  w4, 0x391c0cb3c5c95a63);	\
	w5 = s1(w3) + w14 + s0(w6) + w5;				\
	SHA2_STEP(d, e, f, g, h, a, b, c,  w5, 0x4ed8aa4ae3418acb);	\
	w6 = s1(w4) + w15 + s0(w7) + w6;				\
	SHA2_STEP(c, d, e, f, g, h, a, b,  w6, 0x5b9cca4f7763e373);	\
	w7 = s1(w5) + w0 + s0(w8) + w7;					\
	SHA2_STEP(b, c, d, e, f, g, h, a,  w7, 0x682e6ff3d6b2b8a3);	\
	w8 = s1(w6) + w1 + s0(w9) + w8;					\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w8, 0x748f82ee5defb2fc);	\
	w9 = s1(w7) + w2 + s0(w10) + w9;				\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w9, 0x78a5636f43172f60);	\
	w10 = s1(w8) + w3 + s0(w11) + w10;			 	\
	SHA2_STEP(g, h, a, b, c, d, e, f, w10, 0x84c87814a1f0ab72);	\
	w11 = s1(w9) + w4 + s0(w12) + w11;			 	\
	SHA2_STEP(f, g, h, a, b, c, d, e, w11, 0x8cc702081a6439ec);	\
	w12 = s1(w10) + w5 + s0(w13) + w12;				\
	SHA2_STEP(e, f, g, h, a, b, c, d, w12, 0x90befffa23631e28);	\
	w13 = s1(w11) + w6 + s0(w14) + w13;				\
	SHA2_STEP(d, e, f, g, h, a, b, c, w13, 0xa4506cebde82bde9);	\
	w14 = s1(w12) + w7 + s0(w15) + w14;				\
	SHA2_STEP(c, d, e, f, g, h, a, b, w14, 0xbef9a3f7b2c67915);	\
	w15 = s1(w13) + w8 + s0(w0) + w15;			 	\
	SHA2_STEP(b, c, d, e, f, g, h, a, w15, 0xc67178f2e372532b);	\
									\
	w0 = s1(w14) + w9 + s0(w1) + w0;				\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w0, 0xca273eceea26619c);	\
	w1 = s1(w15) + w10 + s0(w2) + w1;			  	\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w1, 0xd186b8c721c0c207);	\
	w2 = s1(w0) + w11 + s0(w3) + w2;				\
	SHA2_STEP(g, h, a, b, c, d, e, f,  w2, 0xeada7dd6cde0eb1e);	\
	w3 = s1(w1) + w12 + s0(w4) + w3;				\
	SHA2_STEP(f, g, h, a, b, c, d, e,  w3, 0xf57d4f7fee6ed178);	\
	w4 = s1(w2) + w13 + s0(w5) + w4;				\
	SHA2_STEP(e, f, g, h, a, b, c, d,  w4, 0x06f067aa72176fba);	\
	w5 = s1(w3) + w14 + s0(w6) + w5;				\
	SHA2_STEP(d, e, f, g, h, a, b, c,  w5, 0x0a637dc5a2c898a6);	\
	w6 = s1(w4) + w15 + s0(w7) + w6;				\
	SHA2_STEP(c, d, e, f, g, h, a, b,  w6, 0x113f9804bef90dae);	\
	w7 = s1(w5) + w0 + s0(w8) + w7;					\
	SHA2_STEP(b, c, d, e, f, g, h, a,  w7, 0x1b710b35131c471b);	\
	w8 = s1(w6) + w1 + s0(w9) + w8;					\
	SHA2_STEP(a, b, c, d, e, f, g, h,  w8, 0x28db77f523047d84);	\
	w9 = s1(w7) + w2 + s0(w10) + w9;				\
	SHA2_STEP(h, a, b, c, d, e, f, g,  w9, 0x32caab7b40c72493);	\
	w10 = s1(w8) + w3 + s0(w11) + w10;			 	\
	SHA2_STEP(g, h, a, b, c, d, e, f, w10, 0x3c9ebe0a15c9bebc);	\
	w11 = s1(w9) + w4 + s0(w12) + w11;			 	\
	SHA2_STEP(f, g, h, a, b, c, d, e, w11, 0x431d67c49c100d4c);	\
	w12 = s1(w10) + w5 + s0(w13) + w12;				\
	SHA2_STEP(e, f, g, h, a, b, c, d, w12, 0x4cc5d4becb3e42b6);	\
	w13 = s1(w11) + w6 + s0(w14) + w13;				\
	SHA2_STEP(d, e, f, g, h, a, b, c, w13, 0x597f299cfc657e2a);	\
	w14 = s1(w12) + w7 + s0(w15) + w14;				\
	SHA2_STEP(c, d, e, f, g, h, a, b, w14, 0x5fcb6fab3ad6faec);	\
	w15 = s1(w13) + w8 + s0(w0) + w15;				\
	SHA2_STEP(b, c, d, e, f, g, h, a, w15, 0x6c44198c4a475817);	\
									\
	aa += a;							\
	bb += b;							\
	cc += c;							\
	dd += d;							\
	ee += e;							\
	ff += f;							\
	gg += g;							\
	hh += h;


extern void pf_sha512 (const unsigned char *in, size_t len, uint64_t digest[8]);
extern void pf_hmac_sha512 (const unsigned char *key, size_t keylen, const unsigned char *in,  size_t len, uint64_t digest[8]);
