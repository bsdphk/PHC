/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 01/08/2005
*/

#ifndef _SHA2_H
#define _SHA2_H

#include <sys/endian.h>

#define li_64(h) 0x##h##ull

#define VOID_RETURN	void
#define INT_RETURN	int

#if defined(__cplusplus)
extern "C"
{
#endif

/* Note that the following function prototypes are the same */
/* for both the bit and byte oriented implementations.  But */
/* the length fields are in bytes or bits as is appropriate */
/* for the version used.  Bit sequences are arrays of bytes */
/* in which bit sequence indexes increase from the most to  */
/* the least significant end of each byte                   */

#if _HF == 0

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

/* type to hold the SHA256 context */

typedef struct
{   uint32_t count[2];
    uint32_t hash[8];
    uint32_t wbuf[16];
} sha256_ctx;

VOID_RETURN sha256_compile(sha256_ctx ctx[1]);
VOID_RETURN sha256_begin(sha256_ctx ctx[1]);
VOID_RETURN sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1]);
VOID_RETURN sha256_end(void *hval, sha256_ctx ctx[1]);
VOID_RETURN sha256(void *hval, const unsigned char data[], unsigned long len);


#endif

#if _HF == 1

#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE  128

#define _64BIT

/* type to hold the SHA384 (and SHA512) context */

typedef struct
{   uint64_t count[2];
    uint64_t hash[8];
    uint64_t wbuf[16];
} sha512_ctx;

VOID_RETURN sha512_compile(sha512_ctx ctx[1]);
VOID_RETURN sha512_begin(sha512_ctx ctx[1]);
VOID_RETURN sha512_hash(const unsigned char data[], unsigned long len, sha512_ctx ctx[1]);
VOID_RETURN sha512_end(void *hval, sha512_ctx ctx[1]);
VOID_RETURN sha512(void *hval, const unsigned char data[], unsigned long len);

#endif

#if defined(__cplusplus)
}
#endif

#endif
