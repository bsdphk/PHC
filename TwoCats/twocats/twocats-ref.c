/*
   TwoCats reference C implementation

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
#include "twocats-internal.h"

// Add the last hashed data into the result.
static void addIntoHash(TwoCats_H *H, uint32_t *hash32, uint32_t parallelism, uint32_t *states) {
    for(uint32_t p = 0; p < parallelism; p++) {
        for(uint32_t i = 0; i < H->len; i++) {
            hash32[i] += states[p*H->len + i];
        }
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

// Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth.
static bool hashBlocks(TwoCats_H *H, uint32_t *state, uint32_t *mem, uint32_t blocklen,
        uint32_t subBlocklen, uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr,
        uint32_t multiplies, uint32_t repetitions, uint8_t lanes) {

    // Do SIMD friendly memory hashing and a scalar CPU friendly parallel multiplication chain
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    for(uint32_t r = 0; r < repetitions; r++) {
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
    return H->HashState(H, state, a);
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static bool hashWithoutPassword(TwoCats_H *H, uint32_t *state, uint32_t *mem, uint32_t p,
        uint64_t blocklen, uint32_t blocksPerThread, uint32_t multiplies, uint32_t repetitions,
        uint8_t lanes, uint32_t parallelism, uint32_t completedBlocks) {

    uint64_t start = blocklen*blocksPerThread*p;
    uint32_t firstBlock = completedBlocks;
    if(completedBlocks == 0) {
        // Initialize the first block of memory
        if(!H->ExpandUint32(H, mem + start, blocklen, state)) {
            return false;
        }
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
        uint64_t fromAddr = blocklen*reversePos;

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*blocksPerThread*(i % parallelism);
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        if(!hashBlocks(H, state, mem, blocklen, blocklen, fromAddr, prevAddr, toAddr,
                multiplies, repetitions, lanes)) {
            return false;
        }
    }
    return true;
}

// Hash memory with password dependent addressing.
static bool hashWithPassword(TwoCats_H *H, uint32_t *state, uint32_t *mem, uint32_t p,
        uint64_t blocklen, uint32_t subBlocklen, uint32_t blocksPerThread, uint32_t multiplies,
        uint32_t repetitions, uint8_t lanes, uint32_t parallelism, uint32_t completedBlocks) {

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
        if(!hashBlocks(H, state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr,
                multiplies, repetitions, lanes)) {
            return false;
        }
    }
    return true;
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

    // Initialize thread states
    uint32_t states[H->len*parallelism];
    if(!H->ExpandUint32(H, states, H->len*parallelism, hash32)) {
        return false;
    }

    for(uint32_t slice = 0; slice < TWOCATS_SLICES; slice++) {
        for(uint32_t p = 0; p < parallelism; p++) {
            if(slice < resistantSlices) {
                if(!hashWithoutPassword(H, states + p*H->len, mem, p, blocklen, blocksPerThread, multiplies,
                        repetitions, lanes, parallelism, slice*blocksPerThread/TWOCATS_SLICES)) {
                    return false;
                }
            } else {
                if(!hashWithPassword(H, states + p*H->len, mem, p, blocklen, subBlocklen, blocksPerThread,
                    multiplies, repetitions, lanes, parallelism, slice*blocksPerThread/TWOCATS_SLICES)) {
                    return false;
                }
            }
        }
    }

    // Apply a crypto-strength hash
    addIntoHash(H, hash32, parallelism, states);
    return H->Hash(H, hash32);
}

// The TwoCats internal password hashing function.  Return false if there is a memory allocation error.
bool TwoCats(TwoCats_H *H, uint32_t *hash32, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint8_t multiplies, uint8_t lanes, uint8_t parallelism, uint32_t blockSize,
        uint32_t subBlockSize, uint8_t overwriteCost) {

    // Allocate memory
    uint32_t *mem = malloc((uint64_t)1024 << stopMemCost);
    if(mem == NULL) {
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
    //TwoCats_DumpMemory("dieharder_data", mem, ((uint64_t)1024 << stopMemCost)/4);
    free(mem);
    return true;
}
