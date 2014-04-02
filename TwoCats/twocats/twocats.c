/*
   TwoCats optimized C version

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <byteswap.h>
#include "twocats-internal.h"

// This include code copied from blake2s.c
#ifdef __AVX2__
#define HAVE_AVX2
#endif
#include "../blake2-sse/blake2-config.h"

#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

// This rotate code is motivated from blake2s-round.h
#ifdef HAVE_AVX2
#define DECLARE_ROTATE256_CONSTS \
    __m256i shuffleVal = _mm256_set_epi8(30, 29, 28, 31, 26, 25, 24, 27, 22, 21, 20, 23, 18, 17, 16, 19, \
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
#define ROTATE_LEFT8_256(s) _mm256_shuffle_epi8(s, shuffleVal)
#endif

#ifndef HAVE_XOP
#ifdef HAVE_SSSE3
#define DECLARE_ROTATE128_CONSTS \
    __m128i shuffleVal = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
#define ROTATE_LEFT8_128(s) _mm_shuffle_epi8(s, shuffleVal)
#else
#define DECLARE_ROTATE128_CONSTS \
    __m128i shiftRightVal = _mm_set_epi32(24, 24, 24, 24); \
    __m128i shiftLeftVal = _mm_set_epi32(8, 8, 8, 8);
#define ROTATE_LEFT8_128(s) _mm_or_si128(_mm_srl_epi32(s, shiftRightVal), _mm_sll_epi32(s, shiftLeftVal))
#endif
#endif

// This structure is shared among all threads.
struct TwoCatsCommonDataStruct {
    uint32_t *mem;
    uint32_t *hash32;
    uint32_t parallelism;
    uint32_t blocklen;
    uint32_t subBlocklen;
    uint32_t blocksPerThread;
    uint32_t repetitions;
    uint8_t multiplies;
    uint8_t lanes;
    uint32_t completedBlocks;
};

// This structure is unique to each memory-hashing thread
struct TwoCatsContextStruct {
    TwoCats_H H;
    struct TwoCatsCommonDataStruct *common;
    uint32_t *state;
    uint32_t p; // This is the memory-thread number
};

// Add the last hashed data into the result.
static void addIntoHash(TwoCats_H *H, uint32_t *hash32, uint32_t parallelism, uint32_t *states) {
    for(uint32_t p = 0; p < parallelism; p++) {
        for(uint32_t i = 0; i < H->len; i++) {
            hash32[i] += states[p*H->len + i];
        }
    }
}

#if defined(HAVE_AVX2)
static void convStateFromUint32ToM256i(uint32_t state[8], __m256i *v) {
    *v = _mm256_set_epi32(state[7], state[6], state[5], state[4], state[3], state[2], state[1], state[0]);
}

// Convert two __m256i to uint32_t[8].
static void convStateFromM256iToUint32(__m256i *v, uint32_t state[8]) {
    uint32_t *p = (uint32_t *)v;
    uint32_t i;
    for(i = 0; i < 8; i++) {
        state[i] = p[i];
    }
}
#endif
#if defined(HAVE_SSE2)
// Convert a uint32_t[8] to two __m128i values. len must be 4 or 8.
static void convStateFromUint32ToM128i(uint32_t state[8], __m128i *v1, __m128i *v2, uint8_t len) {
    *v1 = _mm_set_epi32(state[3], state[2], state[1], state[0]);
    if(len == 8) {
        *v2 = _mm_set_epi32(state[7], state[6], state[5], state[4]);
    }
}

// Convert two __m128i to uint32_t*. len must be 4 or 8.
static void convStateFromM128iToUint32(__m128i *v1, __m128i *v2, uint32_t *state, uint8_t len) {
    uint32_t *p = (uint32_t *)v1;
    uint32_t i;
    for(i = 0; i < 4; i++) {
        state[i] = p[i];
    }
    if(len == 8) {
        p = (uint32_t *)v2;
        for(i = 0; i < 4; i++) {
            state[i+4] = p[i];
        }
    }
}
#endif

/* Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth.
   Basically, it does for every 8 words:
       for(i = 0; i < 8; i++) {
           state[i] = ROTATE_LEFT((state[i] + *p++) ^ *f++, 8);
           *t++ = state[i];
  
   TODO: Optimizations for ARM, and widths other than 8 should be written as well. */
       
static inline void hashBlocksInner(TwoCats_H *H, uint32_t *state, uint32_t *mem,
        uint32_t blocklen, uint32_t subBlocklen, uint64_t fromAddr, uint64_t prevAddr,
        uint64_t toAddr, uint8_t multiplies, uint32_t repetitions, uint8_t lanes) {

    // Do SIMD friendly memory hashing and a scalar CPU friendly parallel multiplication chain
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    bool haveFastCode = false;
    if(lanes == 8) {
#if defined(HAVE_AVX2)
        haveFastCode = true;
        __m256i s;
        convStateFromUint32ToM256i(state, &s);
        __m256i *m = (__m256i *)mem;
        DECLARE_ROTATE256_CONSTS
        __m256i *f;
        __m256i *t;
        __m256i *p;
        for(uint32_t r = 0; r < repetitions-1; r++) {
            f = m + fromAddr/8;
            for(uint32_t i = 0; i < numSubBlocks; i++) {
                uint32_t randVal = *(uint32_t *)f;
                p = m + prevAddr/8 + (subBlocklen/8)*(randVal & (numSubBlocks - 1));
                for(uint32_t j = 0; j < subBlocklen/8; j++) {

                    // Compute the multiplication chain
                    for(uint8_t k = 0; k < multiplies; k++) {
                        a ^= (uint64_t)b*c >> 32;
                        b += c;
                        c ^= (uint64_t)a*d >> 32;
                        d += a;
                    }

                    // Hash 32 bytes of memory
                    s = _mm256_add_epi32(s, *p++);
                    s = _mm256_xor_si256(s, *f++);
                    s = ROTATE_LEFT8_256(s);
                }
            }
        }
        f = m + fromAddr/8;
        t = m + toAddr/8;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *(uint32_t *)f;
            p = m + prevAddr/8 + (subBlocklen/8)*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/8; j++) {

                // Compute the multiplication chain
                for(uint8_t k = 0; k < multiplies; k++) {
                    a ^= (uint64_t)b*c >> 32;
                    b += c;
                    c ^= (uint64_t)a*d >> 32;
                    d += a;
                }

                // Hash 32 bytes of memory
                s = _mm256_add_epi32(s, *p++);
                s = _mm256_xor_si256(s, *f++);
                s = ROTATE_LEFT8_256(s);
                *t++ = s;
            }
        }
        convStateFromM256iToUint32(&s, state);
#elif defined(HAVE_SSE2)
        haveFastCode = true;
        __m128i s1;
        __m128i s2;
        convStateFromUint32ToM128i(state, &s1, &s2, 8);
        __m128i *m = (__m128i *)mem;
        DECLARE_ROTATE128_CONSTS
        __m128i *f;
        __m128i *t;
        __m128i *p;
        for(uint32_t r = 0; r < repetitions-1; r++) {
            f = m + fromAddr/4;
            for(uint32_t i = 0; i < numSubBlocks; i++) {
                uint32_t randVal = *(uint32_t *)f;
                p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
                for(uint32_t j = 0; j < subBlocklen/8; j++) {

                    // Compute the multiplication chain
                    for(uint8_t k = 0; k < multiplies; k++) {
                        a ^= (uint64_t)b*c >> 32;
                        b += c;
                        c ^= (uint64_t)a*d >> 32;
                        d += a;
                    }

                    // Hash 32 bytes of memory
                    s1 = _mm_add_epi32(s1, *p++);
                    s1 = _mm_xor_si128(s1, *f++);
                    // Rotate left 8
                    s1 = ROTATE_LEFT8_128(s1);
                    s2 = _mm_add_epi32(s2, *p++);
                    s2 = _mm_xor_si128(s2, *f++);
                    // Rotate left 8
                    s2 = ROTATE_LEFT8_128(s2);
                }
            }
        }
        f = m + fromAddr/4;
        t = m + toAddr/4;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *(uint32_t *)f;
            p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/8; j++) {

                // Compute the multiplication chain
                for(uint8_t k = 0; k < multiplies; k++) {
                    a ^= (uint64_t)b*c >> 32;
                    b += c;
                    c ^= (uint64_t)a*d >> 32;
                    d += a;
                }

                // Hash 32 bytes of memory
                s1 = _mm_add_epi32(s1, *p++);
                s1 = _mm_xor_si128(s1, *f++);
                // Rotate left 8
                s1 = ROTATE_LEFT8_128(s1);
                *t++ = s1;
                s2 = _mm_add_epi32(s2, *p++);
                s2 = _mm_xor_si128(s2, *f++);
                // Rotate left 8
                s2 = ROTATE_LEFT8_128(s2);
                *t++ = s2;
            }
        }
        convStateFromM128iToUint32(&s1, &s2, state, 8);
#endif
    } else if(lanes == 4) {
#if defined(HAVE_SSE2)
        haveFastCode = true;
        __m128i s;
        convStateFromUint32ToM128i(state, &s, &s, 4);
        __m128i *m = (__m128i *)mem;
        DECLARE_ROTATE128_CONSTS
        __m128i *f;
        __m128i *t;
        __m128i *p;
        for(uint32_t r = 0; r < repetitions-1; r++) {
            f = m + fromAddr/4;
            for(uint32_t i = 0; i < numSubBlocks; i++) {
                uint32_t randVal = *(uint32_t *)f;
                p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
                for(uint32_t j = 0; j < subBlocklen/4; j++) {

                    // Compute the multiplication chain
                    for(uint8_t k = 0; k < multiplies; k++) {
                        a ^= (uint64_t)b*c >> 32;
                        b += c;
                        c ^= (uint64_t)a*d >> 32;
                        d += a;
                    }

                    // Hash 16 bytes of memory
                    s = _mm_add_epi32(s, *p++);
                    s = _mm_xor_si128(s, *f++);
                    // Rotate left 8
                    s = ROTATE_LEFT8_128(s);
                }
            }
        }
        f = m + fromAddr/4;
        t = m + toAddr/4;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *(uint32_t *)f;
            p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/4; j++) {

                // Compute the multiplication chain
                for(uint8_t k = 0; k < multiplies; k++) {
                    a ^= (uint64_t)b*c >> 32;
                    b += c;
                    c ^= (uint64_t)a*d >> 32;
                    d += a;
                }

                // Hash 16 bytes of memory
                s = _mm_add_epi32(s, *p++);
                s = _mm_xor_si128(s, *f++);
                // Rotate left 8
                s = ROTATE_LEFT8_128(s);
                *t++ = s;
            }
        }
        convStateFromM128iToUint32(&s, &s, state, 4);
#endif
    } else if(lanes == 2) {
        // TODO: write 2-lane code here using MMX
    }
    if(!haveFastCode) {
        for(uint32_t r = 0; r < repetitions-1; r++) {
            uint32_t *f = mem + fromAddr;
            for(uint32_t i = 0; i < numSubBlocks; i++) {
                uint32_t randVal = *f;
                uint32_t *p = mem + prevAddr + subBlocklen*(randVal & (numSubBlocks - 1));
                for(uint32_t j = 0; j < subBlocklen/lanes; j++) {

                    // Compute the multiplication chain
                    for(uint32_t k = 0; k < multiplies; k++) {
                        a ^= (uint64_t)b*c >> 32;
                        b += c;
                        c ^= (uint64_t)a*d >> 32;
                        d += a;
                    }

                    // Hash lanes of memory
                    for(uint32_t k = 0; k < lanes; k++) {
                        state[k] = (state[k] + *p++) ^ *f++;
                        state[k] = (state[k] >> 24) | (state[k] << 8);
                    }
                }
            }
        }
        uint32_t *f = mem + fromAddr;
        uint32_t *t = mem + toAddr;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *f;
            uint32_t *p = mem + prevAddr + subBlocklen*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/lanes; j++) {

                // Compute the multiplication chain
                for(uint32_t k = 0; k < multiplies; k++) {
                    a ^= (uint64_t)b*c >> 32;
                    b += c;
                    c ^= (uint64_t)a*d >> 32;
                    d += a;
                }

                // Hash lanes of memory
                for(uint32_t k = 0; k < lanes; k++) {
                    state[k] = (state[k] + *p++) ^ *f++;
                    state[k] = (state[k] >> 24) | (state[k] << 8);
                    *t++ = state[k];
                }
            }
        }
    }
    H->HashState(H, state, a);
}

// This crazy wrapper is simply to force to optimizer to unroll the lanes loop.
static inline void hashBlocksLanes(TwoCats_H *H, uint32_t state[8], uint32_t *mem, uint32_t blocklen,
        uint32_t subBlocklen, uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr,
        uint8_t multiplies, uint32_t repetitions, uint8_t lanes) {
    switch(lanes) {
    case 1:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, 1);
        break;
    case 2:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, 2);
        break;
    case 4:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, 4);
        break;
    case 8:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, 8);
        break;
    case 16:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, 16);
        break;
    default:
        hashBlocksInner(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions, lanes);
    }
}

// This crazy wrapper is simply to force to optimizer to unroll the multiplication loop.
static inline void hashBlocks(TwoCats_H *H, uint32_t state[8], uint32_t *mem, uint32_t blocklen,
        uint32_t subBlocklen, uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr,
        uint8_t multiplies, uint32_t repetitions, uint8_t lanes) {
    switch(multiplies) {
    case 0:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 0, repetitions, lanes);
        break;
    case 1:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 1, repetitions, lanes);
        break;
    case 2:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 2, repetitions, lanes);
        break;
    case 3:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 3, repetitions, lanes);
        break;
    case 4:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 4, repetitions, lanes);
        break;
    case 5:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 5, repetitions, lanes);
        break;
    case 6:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 6, repetitions, lanes);
        break;
    case 7:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 7, repetitions, lanes);
        break;
    case 8:
        hashBlocksLanes(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, 8, repetitions, lanes);
        break;
    }
}

// Bit-reversal function derived from Catena's version.
static inline uint32_t reverse(uint32_t x, const uint8_t n)
{
    if(n == 0) {
        return 0;
    }
    x = bswap_32(x);
    x = ((x & 0x0f0f0f0f) << 4) | ((x & 0xf0f0f0f0) >> 4);
    x = ((x & 0x33333333) << 2) | ((x & 0xcccccccc) >> 2);
    x = ((x & 0x55555555) << 1) | ((x & 0xaaaaaaaa) >> 1);
    return x >> (32 - n);
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static void *hashWithoutPassword(void *contextPtr) {
    struct TwoCatsContextStruct *ctx = (struct TwoCatsContextStruct *)contextPtr;
    struct TwoCatsCommonDataStruct *c = ctx->common;

    TwoCats_H *H = &(ctx->H);
    uint32_t *state = ctx->state;
    uint32_t *mem = c->mem;
    uint32_t p = ctx->p;
    uint32_t blocklen = c->blocklen;
    uint32_t blocksPerThread = c->blocksPerThread;
    uint8_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;
    uint32_t lanes = c->lanes;
    uint32_t parallelism = c->parallelism;
    uint32_t completedBlocks = c->completedBlocks;

    uint64_t start = blocklen*blocksPerThread*p;
    uint32_t firstBlock = completedBlocks;
    if(completedBlocks == 0) {
        // Initialize the first block of memory
        H->ExpandUint32(H, mem + start, blocklen, state);
        firstBlock = 1;
    }

    // Hash one "slice" worth of memory hashing
    uint32_t numBits = 1; // The number of bits in i
    for(uint32_t i = firstBlock; i < completedBlocks + blocksPerThread/TWOCATS_SLICES; i++) {
        while(1 << numBits <= i) {
            numBits++;
        }

        // Compute the "sliding reverse" block position
        uint32_t reversePos = reverse(i, numBits-1);
        if(reversePos + (1 << (numBits-1)) < i) {
            reversePos += 1 << (numBits-1);
        }

        // Hash the prior block and the block at reversePos and write the result
        uint64_t fromAddr = blocklen*reversePos;

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*blocksPerThread*(i % parallelism);
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        hashBlocks(H, state, mem, blocklen, blocklen, fromAddr, prevAddr, toAddr,
            multiplies, repetitions, lanes);
    }
    pthread_exit(NULL);
}

// Hash memory with password dependent addressing.
static void *hashWithPassword(void *contextPtr) {
    struct TwoCatsContextStruct *ctx = (struct TwoCatsContextStruct *)contextPtr;
    struct TwoCatsCommonDataStruct *c = ctx->common;

    TwoCats_H *H = &(ctx->H);
    uint32_t *state = ctx->state;
    uint32_t *mem = c->mem;
    uint32_t p = ctx->p;
    uint64_t blocklen = c->blocklen;
    uint32_t subBlocklen = c->subBlocklen;
    uint32_t blocksPerThread = c->blocksPerThread;
    uint8_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;
    uint8_t lanes = c->lanes;
    uint32_t parallelism = c->parallelism;
    uint32_t completedBlocks = c->completedBlocks;

    uint64_t start = blocklen*blocksPerThread*p;

    // Hash one "slice" worth of memory hashing
    for(uint32_t i = completedBlocks; i < completedBlocks + blocksPerThread/TWOCATS_SLICES; i++) {

        // Compute rand()^3 distance distribution
        uint64_t v = state[0];
        uint64_t v2 = v*v >> 32;
        uint64_t v3 = v*v2 >> 32;
        uint32_t distance = (i-1)*v3 >> 32;

        // Hash the prior block and the block at 'distance' blocks in the past
        uint64_t fromAddr = (i - 1 - distance)*blocklen;

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*(state[1] % parallelism)*blocksPerThread;
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        hashBlocks(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr,
            multiplies, repetitions, lanes);
    }
    pthread_exit(NULL);
}

// Hash memory for one level of garlic.
static bool hashMemory(TwoCats_H *H, uint32_t *hash32, uint32_t *mem, uint8_t memCost,
        uint8_t timeCost, uint8_t multiplies, uint8_t lanes, uint8_t parallelism,
        uint32_t blockSize, uint32_t subBlockSize, uint32_t resistantSlices) {

    uint64_t memlen = (1024/sizeof(uint32_t)) << memCost;
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t subBlocklen = subBlockSize/sizeof(uint32_t);
    uint32_t blocksPerThread = TWOCATS_SLICES*(memlen/(TWOCATS_SLICES * parallelism * blocklen));
    uint32_t repetitions = 1 << timeCost;


    // Fill out the common constant data used in all threads
    pthread_t memThreads[parallelism];
    struct TwoCatsContextStruct c[parallelism];
    struct TwoCatsCommonDataStruct common;
    common.multiplies = multiplies;
    common.lanes = lanes;
    common.mem = mem;
    common.hash32 = hash32;
    common.blocklen = blocklen;
    common.subBlocklen = subBlocklen;
    common.blocksPerThread = blocksPerThread;
    common.parallelism = parallelism;
    common.repetitions = repetitions;

    // Initialize thread states
    uint32_t states[H->len*parallelism];
    H->ExpandUint32(H, states, H->len*parallelism, hash32);
    for(uint32_t p = 0; p < parallelism; p++) {
        c[p].common = &common;
        c[p].p = p;
        c[p].state = states + p*H->len;
        TwoCats_InitHash(&(c[p].H), H->type);
    }

    for(uint32_t slice = 0; slice < TWOCATS_SLICES; slice++) {
        common.completedBlocks = slice*blocksPerThread/TWOCATS_SLICES;
        for(uint32_t p = 0; p < parallelism; p++) {
            int rc;
            if(slice < resistantSlices) {
                rc = pthread_create(&memThreads[p], NULL, hashWithoutPassword, (void *)(c + p));
            } else {
                rc = pthread_create(&memThreads[p], NULL, hashWithPassword, (void *)(c + p));
            }
            if(rc) {
                fprintf(stderr, "Unable to start threads\n");
                return false;
            }
        }
        for(uint32_t p = 0; p < parallelism; p++) {
            (void)pthread_join(memThreads[p], NULL);
        }
    }

    // Apply a crypto-strength hash
    addIntoHash(H, hash32, parallelism, states);
    H->Hash(H, hash32);
    return true;
}

// The TwoCats password hashing function.  Return false if there is a memory allocation error.
bool TwoCats(TwoCats_H *H, uint32_t *hash32, uint8_t startMemCost, uint8_t stopMemCost,
        uint8_t timeCost, uint8_t multiplies, uint8_t lanes, uint8_t parallelism, uint32_t blockSize,
        uint32_t subBlockSize, uint8_t overwriteCost) {

    // Allocate memory
    uint32_t *mem;
    if(posix_memalign((void *)&mem,  64, (uint64_t)1024 << stopMemCost)) {
        fprintf(stderr, "Unable to allocate memory\n");
        return false;
    }

    // Iterate through the levels of garlic.  Throw away some early memory to reduce the
    // danger from leaking memory to an attacker.
    for(uint8_t i = 0; i <= stopMemCost; i++) {
        if(i >= startMemCost || i < overwriteCost) {
            if(((uint64_t)1024 << i)/(parallelism*blockSize) >= TWOCATS_SLICES) {
                uint32_t resistantSlices = TWOCATS_SLICES/2;
                if(i < startMemCost) {
                    resistantSlices = TWOCATS_SLICES;
                }
                if(!hashMemory(H, hash32, mem, i, timeCost, multiplies, lanes, parallelism,
                        blockSize, subBlockSize, resistantSlices)) {
                    free(mem);
                    return false;
                }
            }
            // Not doing the last hash is for server relief support
            if(i != stopMemCost && !H->Hash(H, hash32)) {
                return false;
            }
        }
    }

    // The light is green, the trap is clean
    free(mem);
    return true;
}
