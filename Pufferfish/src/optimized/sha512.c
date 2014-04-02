/* sha512.c - optimized single block sha512 implementation.
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */ 

#include <stdint.h>
#include "sha512.h"

void pf_sha512 (const unsigned char *in, size_t len, uint64_t digest[8])
{
        int i, j;
        unsigned char buf[128] = {0};

        uint64_t tmp1 = 0, tmp2 = 0;

        uint64_t a,  b,  c,  d,  e,  f,  g,  h,
                 aa, bb, cc, dd, ee, ff, gg, hh;

        uint64_t w0  = 0, w1  = 0, w2  = 0, w3  = 0,
                 w4  = 0, w5  = 0, w6  = 0, w7  = 0,
                 w8  = 0, w9  = 0, w10 = 0, w11 = 0,
                 w12 = 0, w13 = 0, w14 = 0, w15 = 0;

        uint64_t *w[14];

        w[ 0] = &w0;  w[ 1] = &w1;  w[ 2] = &w2;  w[ 3] = &w3,
        w[ 4] = &w4;  w[ 5] = &w5;  w[ 6] = &w6;  w[ 7] = &w7;
        w[ 8] = &w8;  w[ 9] = &w9;  w[10] = &w10; w[11] = &w11;
        w[12] = &w12; w[13] = &w13; w[14] = &w14;

        for (i = 0; i < len; i++)
                buf[i] = in[i];
        buf[len] = 0x80;

        for (i=0, j=0; i < len + 1 && j < 15; i+=8, j++)
                uchar_to_uint64 (*w[j], buf, i);
        w15 = len << 3;

        aa = 0x6a09e667f3bcc908;
        bb = 0xbb67ae8584caa73b;
        cc = 0x3c6ef372fe94f82b;
        dd = 0xa54ff53a5f1d36f1;
        ee = 0x510e527fade682d1;
        ff = 0x9b05688c2b3e6c1f;
        gg = 0x1f83d9abfb41bd6b;
        hh = 0x5be0cd19137e2179;

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
