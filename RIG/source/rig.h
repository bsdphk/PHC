
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "BLAKE/blake2.h"

#ifndef RECTANGLE_H_
#define RECTANGLE_H_

typedef uint8_t byte;
typedef uint32_t u32;
typedef uint64_t u64;

inline int BLAKE512(unsigned char *in, unsigned long long inlen, unsigned char *out)
{
	return blake2b(out, in, NULL, BLAKE2B_OUTBYTES, inlen, 0);
}

//#define COUNT_32 0

#ifdef COUNT_32

#define COUNT_TYPE u32
#define CNT_LEN_BYTES   4
#else

#define COUNT_TYPE		u64
#define CNT_LEN_BYTES	8

#endif
//////////////////////////
#define HASH_SHA_512 0

#ifdef HASH_SHA_256

#define OUTPUT_BITS		 256
#define HASH SHA256
#define HASH_LEN_BYTES   32
#else

#define OUTPUT_BITS		 512
#define HASH BLAKE512       
#define HASH_LEN_BYTES_OUT   64
#define HASH_LEN_BYTES_KS    56
#endif
/////////////////////////
//#define HASH_LEN_BYTES 64
#define SALT_LEN_BYTES 16

#define LAYER_LENGTH  (CNT_LEN_BYTES + HASH_LEN_BYTES_OUT + HASH_LEN_BYTES_KS)

typedef byte HashData[HASH_LEN_BYTES_KS];
typedef byte AlphaData[HASH_LEN_BYTES_OUT];

#define SUCCESS					0

#define ERROR_TIME_LESS			101
#define ERROR_COST_LESS			102
#define ERROR_COST_MORE			103
#define ERROR_SALTLEN_INVALID	104
#define ERROR_COST_MULTIPLE		105

#define ERROR_INVALID_OUT_HLEN	106

const char * GetError(int Error);
void LongToBytes(COUNT_TYPE val, byte b[CNT_LEN_BYTES]) ;

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);


static uint8_t PI_CONST[64] = {  0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
								 0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
								 0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C,
								 0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17 };

#define _SWAP(x,s,m) (((x) >>(s)) & (m)) | (((x) & (m))<<(s))

static u64 BitReverse64(u64 value)
{	
	value = _SWAP(value, 32,  0x00000000FFFFFFFFull);
	value = _SWAP(value, 16,  0x0000FFFF0000FFFFull);
	value = _SWAP(value, 8,   0x00FF00FF00FF00FFull);
	value = _SWAP(value, 4,   0x0F0F0F0F0F0F0F0Full);
	value = _SWAP(value, 2,   0x3333333333333333ull);
	value = _SWAP(value, 1,   0x5555555555555555ull);

	return value;
}

static u32 BitReverse32(register u32 x)
{
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
    return((x >> 16) | (x << 16));
}

#endif


void LongToBytes(COUNT_TYPE val, byte* b);

