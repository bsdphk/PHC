/*
   SkinnyCat C reference implementation

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright and
   related and neighboring rights to this software to the public domain worldwide. This
   software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with this
   software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "../blake2-ref/blake2.h"
#include "skinnycat.h"

#define BLOCKLEN 4096

// Prevents compiler optimizing out memset() -- from blake2-impl.h
static inline void secureZeroMemory(void *v, uint32_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while(n--) {
        *p++ = 0;
    }
}

// Encode a length len/4 vector of (uint32_t) into a length len vector of
// (unsigned char) in little-endian form.  Assumes len is a multiple of 4.
static inline void encodeLittleEndian(uint8_t *dst, const uint32_t *src, uint32_t len) {
    uint8_t *p = dst;
    for (uint32_t i = 0; i < len / 4; i++) {
        *p++ = *src;
        *p++ = *src >> 8;
        *p++ = *src >> 16;
        *p++ = *src++ >> 24;
    }
}

// Decode a little-endian length len vector of (unsigned char) into a length
// len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
static inline void decodeLittleEndian(uint32_t *dst, const uint8_t *src, uint32_t len) {
    const uint8_t *p = src;
    for(uint32_t i = 0; i < len / 4; i++) {
        dst[i] = ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) + ((uint32_t)(p[2]) << 16) +
            ((uint32_t)(p[3]) << 24));
        p += 4;
    }
}

// Hash the data with a secure hash function.
static bool H(SkinnyCat_HashType hashType, uint8_t out[32], const uint8_t *in, uint32_t inSize) {
    switch(hashType) {
    case SKINNYCAT_BLAKE2S:
        return !blake2s(out, in, NULL, 32, inSize, 0);
    case SKINNYCAT_SHA256:
        return SHA256(in, inSize, out) != NULL;
    default:
        fprintf(stderr, "Unknown hash type\n");
    }
    return false;
}

// Hash between lanes with the secure hash function.
static void hashState(SkinnyCat_HashType hashType, uint32_t out[8], uint32_t in[8], uint32_t a) {
    uint8_t inBuf[36];
    uint8_t outBuf[32];
    encodeLittleEndian(inBuf, in, 32);
    encodeLittleEndian(inBuf + 32, &a, 4);
    H(hashType, outBuf, inBuf, 36);
    decodeLittleEndian(out, outBuf, 32);
}

// Fill memmory with pseudo-random data using H.
static void expand(SkinnyCat_HashType hashType, uint32_t *mem, uint32_t len, uint32_t state[8]) {
    for(uint32_t count = 0; count < len/8; count++) {
        hashState(hashType, mem + count*8, state, count);
    }
}

// Compute the bit reversal of v.
static uint32_t reverse(uint32_t v, uint32_t numBits) {
    uint32_t result = 0;
    while(numBits-- != 0) {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    return result;
}

// Find the sliding reverse position of the prior block.
static uint32_t slidingReverse(uint32_t i) {
    uint32_t numBits = 1;
    while((1 << numBits) <= i) {
        numBits++;
    }
    uint32_t reversePos = reverse(i, numBits-1);
    if(reversePos + (1 << (numBits-1)) < i) {
        reversePos += 1 << (numBits-1);
    }
    return reversePos;
}

// Find the distance to the prior block using a cubed distribution.
static uint32_t distanceCubed(uint32_t i, uint64_t v) {
    uint64_t v2 = v*v >> 32;
    uint64_t v3 = v*v2 >> 32;
    return (i-1)*v3 >> 32;
}

// Add the last hashed data into the result.
static void addIntoHash(uint32_t *hash32, uint32_t *states) {
    for(uint32_t i = 0; i < 8; i++) {
        hash32[i] += states[i];
    }
}

// Derive pseudorandom key from password and salt in a TwoCats compatible manner.
static void deriveKey(SkinnyCat_HashType hashType, uint32_t *hash32, uint8_t *password,
        uint8_t passwordSize, const uint8_t *salt, uint8_t saltSize, uint8_t memCost,
        uint32_t blocklen) {
    uint8_t hash[32];
    uint32_t tweakSize = 5*sizeof(uint32_t) + 6 + saltSize + passwordSize;
    uint32_t data32[5] = {passwordSize, saltSize, 0, blocklen*4, blocklen*4};
    uint8_t data8[6] = {memCost, 0, 0, 8, 1, 0};
    uint8_t tweak[tweakSize];
    encodeLittleEndian(tweak, data32, 20);
    memcpy(tweak + 20, data8, 6);
    memcpy(tweak + 26, password, passwordSize);
    memcpy(tweak + 26 + passwordSize, salt, saltSize);
    H(hashType, hash, tweak, tweakSize); // Same as Twocat's extract
    decodeLittleEndian(hash32, hash, 32);
    secureZeroMemory(tweak, tweakSize);
    secureZeroMemory(hash, 32);
}

// The SkinnyCat main API.
bool SkinnyCat_HashPassword(SkinnyCat_HashType hashType, uint8_t *hash, uint8_t *password,
        uint8_t passwordSize, const uint8_t *salt, uint8_t saltSize, uint8_t memCost,
        bool clearPassword) {

    // Choose smaller blocklen for smaller memCost values
    uint64_t memlen = ((uint64_t)1024 << memCost)/sizeof(uint32_t);
    uint32_t blocklen = BLOCKLEN;
    while(blocklen > 8 && memlen/blocklen < 256) {
        blocklen >>= 1;
    }
    
    // Derive the initial pseudorandom key
    uint32_t PRK[8];
    deriveKey(hashType, PRK, password, passwordSize, salt, saltSize, memCost, blocklen);

    if(clearPassword) {
        secureZeroMemory(password, passwordSize);
    }

    uint32_t *mem = malloc(memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }

    // Initialize state
    uint32_t state[8];
    hashState(hashType, state, PRK, 0);

    // Initialize first block of memory
    expand(hashType, mem, blocklen, state);

    // Hash without password dependent addressing
    uint64_t prevAddr = 0;
    uint64_t toAddr = blocklen;
    for(uint32_t i = 1; i < memlen/(2*blocklen); i++) {
        uint32_t a = state[0]; // For compatibility with TwoCats
        uint64_t fromAddr = slidingReverse(i)*blocklen;
        for(uint32_t j = 0; j < blocklen/8; j++) {
            for(uint32_t k = 0; k < 8; k++) {
                state[k] = (state[k] + mem[prevAddr++]) ^ mem[fromAddr++];
                state[k] = (state[k] >> 24) | (state[k] << 8);
                mem[toAddr++] = state[k];
            }
        }
        hashState(hashType, state, state, a);
    }

    // Hash with password dependent addressing
    for(uint32_t i = memlen/(2*blocklen); i < memlen/blocklen; i++) {
        uint32_t a = state[0]; // For compatibility with TwoCats
        uint64_t fromAddr = (i - 1 - distanceCubed(i, state[0]))*blocklen;
        for(uint32_t j = 0; j < blocklen/8; j++) {
            for(uint32_t k = 0; k < 8; k++) {
                state[k] = (state[k] + mem[prevAddr++]) ^ mem[fromAddr++];
                state[k] = (state[k] >> 24) | (state[k] << 8);
                mem[toAddr++] = state[k];
            }
        }
        hashState(hashType, state, state, a);
    }

    // Add result into original hash, and hash it one more time
    addIntoHash(PRK, state);
    encodeLittleEndian(hash, PRK, 32);
    H(hashType, hash, hash, 32);

    // One final hash for compatibility with TwoCat's server relief
    H(hashType, hash, hash, 32);
    return true;
}

// This is the prototype required for the password hashing competition.  It uses Blake2s.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    if(outlen != 32) {
        fprintf(stderr, "outlen must be 32\n");
        return 1;
    }
    return !SkinnyCat_HashPassword(SKINNYCAT_BLAKE2S, out, (uint8_t *)in, inlen, salt, saltlen, m_cost, false);
}

#if defined(SKINNYCAT_TEST)

// Print the hash value in hex.
static void printHex(char *message, uint8_t *data, uint8_t len) {
    printf("%s", message);
    for(uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static char *hashNames[2] = {"blake2s", "SHA256"};

// Print a test vector.
static void printTest(SkinnyCat_HashType hashType, uint8_t *password, uint8_t passwordSize,
        uint8_t *salt, uint8_t saltSize, uint8_t memCost) {
    printf("%s ", hashNames[hashType]);
    printHex("password:", password, passwordSize);
    printHex(" salt:", salt, saltSize);
    printf(" memCost:%u ", memCost);
    uint8_t hash[32];
    SkinnyCat_HashPassword(SKINNYCAT_BLAKE2S, hash, password, passwordSize, salt, saltSize, memCost, false);
    printHex("-> ", hash, 32);
    printf("\n");
}

// Print test vectors.
static void printTestVectors(SkinnyCat_HashType hashType) {
    // Verify we can run without password or salt
    printTest(hashType, NULL, 0, NULL, 0, 0);
    // Verify password and salt from 0 to 255 for memCost 0 .. 9
    for(uint32_t i = 0; i < 256; i++) {
        uint8_t v = i;
        for(uint32_t j = 0; j < 10; j++) {
            printTest(hashType, &v, 1, NULL, 0, j);
        }
        for(uint32_t j = 0; j < 10; j++) {
            printTest(hashType, NULL, 0, &v, 1, j);
        }
        for(uint32_t j = 0; j < 10; j++) {
            printTest(hashType, &v, 1, &v, 1, j);
        }
    }
}

int main(int argc, char **argv) {
    uint8_t memCost = 20;
    uint8_t hash[32];
    if(argc > 2) {
        fprintf(stderr, "Usage: skinnycat [memCost]\n");
        return 1;
    } else if(argc == 2) {
        memCost = atoi(argv[1]);
        SkinnyCat_HashPassword(SKINNYCAT_BLAKE2S, hash, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, memCost, false);
        printHex("result:", hash, 32);
        printf("\n");
    } else {
        printTestVectors(SKINNYCAT_BLAKE2S);
        printTestVectors(SKINNYCAT_SHA256);
    }
    return 0;
}

#endif
