/*
   TwoCats common functions between reference and optimized C versions.

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
#include <strings.h>
#include <time.h>
#include "twocats-internal.h"

// Print the state.
void TwoCats_PrintState(char *message, uint32_t *state, uint32_t length) {
    printf("%s\n", message);
    for(uint32_t i = 0; i < length; i++) {
        printf("%u ", state[i]);
    }
    printf("\n");
}

// Print a value out in hex - from Catena.
void TwoCats_PrintHex(char *message, uint8_t *x, int len) {
    puts(message);
    for(uint32_t i = 0; i < len; i++) {
        if(i != 0 && i % 8 == 0) {
            puts("");
        }
        printf("%02x ", x[i]);
    }
    printf("     %d (octets)\n\n", len);
}

// Just dump memory in a format that can be passed to the dieharder tests with:
//   dieharder -a -g 202 -f dieharder_data
void TwoCats_DumpMemory(char *fileName, uint32_t *mem, uint64_t memlen) {
    FILE *file = fopen(fileName, "w");
    if(file == NULL) {
        fprintf(stderr, "Unable to open file %s for writing\n", fileName);
        return;
    }
    fprintf(file, "type: d\n");
    fprintf(file, "count: %lu\n", memlen);
    fprintf(file, "numbit: 32\n");
    for(uint64_t i = 0; i < memlen; i++) {
        fprintf(file, "%u\n", mem[i]);
    }
    fclose(file);
}

// Hash a 32-bit value into the current state.
static bool updateUint32(TwoCats_H *H, uint32_t value) {
    uint8_t buf[sizeof(uint32_t)];
    encodeLittleEndian(buf, &value, 4);
    if(!H->Update(H, buf, sizeof(uint32_t))) {
        return false;
    }
    return true;
}

// Scramble the hash value.
static bool scrambleHash(TwoCats_H *H, uint32_t *hash32) {
    uint8_t buf[H->size];
    encodeLittleEndian(buf, hash32, H->size);
    if(!H->Init(H) || !H->Update(H, buf, H->size) || !H->Final(H, buf)) {
        secureZeroMemory(buf, H->size);
        return false;
    }
    decodeLittleEndian(hash32, buf, H->size);
    secureZeroMemory(buf, H->size);
    return true;
}

// Scramble the 32-bit hash state, including a single uint32_t value.
static bool hashState(TwoCats_H *H, uint32_t *state, uint32_t value) {
    uint8_t buf[H->size];
    encodeLittleEndian(buf, state, H->size);
    if(!H->Init(H) || !H->Update(H, buf, H->size) ||
            !H->UpdateUint32(H, value) || !H->Final(H, buf)) {
        secureZeroMemory(buf, H->size);
        return false;
    }
    decodeLittleEndian(state, buf, H->size);
    secureZeroMemory(buf, H->size);
    return true;
}

// Expand a fixed length hash to a variable length hash of uint32_t's.
static bool expandUint32(TwoCats_H *H, uint32_t *out, uint32_t outlen, const uint32_t *hash32) { 
    for(uint32_t i = 0; i < outlen/H->len; i++) {
        memcpy(out + i*H->len, hash32, H->len*sizeof(uint32_t));
        if(!hashState(H, out + i*H->len, i)) {
            return false;
        }
    }
    return true;
}

// Finalize a hash and convert to an array of uint32_t.
static bool finalUint32(TwoCats_H *H, uint32_t *hash32) {
    uint8_t buf[H->size];
    if(!H->Final(H, buf)) {
        secureZeroMemory(buf, H->size);
        return false;
    }
    decodeLittleEndian(hash32, buf, H->size);
    secureZeroMemory(buf, H->size);
    return true;
}

// Initialize a hashing object.
void TwoCats_InitHash(TwoCats_H *H, TwoCats_HashType type) {
    memset(H, 0, sizeof(TwoCats_H));
    H->type = type;
    H->UpdateUint32 = updateUint32;
    H->Hash = scrambleHash;
    H->HashState = hashState;
    H->FinalUint32 = finalUint32;
    H->ExpandUint32 = expandUint32;
    switch(type) {
    case TWOCATS_BLAKE2S: TwoCats_InitBlake2s(H); break;
    case TWOCATS_BLAKE2B: TwoCats_InitBlake2b(H); break;
    case TWOCATS_SHA256: TwoCats_InitSHA256(H); break;
    case TWOCATS_SHA512: TwoCats_InitSHA512(H); break;
    default:
        fprintf(stderr, "Unknown hash type\n");
        exit(1);
    }
    H->len = H->size/4;
}

// Just return the hash type's name.
char *TwoCats_GetHashTypeName(TwoCats_HashType hashType) {
    TwoCats_H H;
    TwoCats_InitHash(&H, hashType);
    return H.name;
}

// Return the size of the hash type.
uint8_t TwoCats_GetHashTypeSize(TwoCats_HashType hashType) {
    TwoCats_H H;
    TwoCats_InitHash(&H, hashType);
    return H.size;
}

// Find a hash type with the given name.
TwoCats_HashType TwoCats_FindHashType(char *name) {
    TwoCats_H H;
    for(uint32_t i = 0; i < TWOCATS_NONE; i++) {
        TwoCats_InitHash(&H, i);
        if(!strcmp(H.name, name)) {
            return i;
        }
    }
    return TWOCATS_NONE;
}

// Verify that parameters are valid for password hashing.
static bool verifyParameters(TwoCats_H *H, uint8_t startMemCost, uint8_t stopMemCost,
        uint8_t timeCost, uint8_t multiplies, uint8_t lanes, uint8_t parallelism,
        uint32_t blockSize, uint32_t subBlockSize) {

    if(H->len < lanes || lanes == 0) {
        fprintf(stderr, "Invalid lanes size: the range is 1 through %u for %s\n", H->len,
            TwoCats_GetHashTypeName(H->type));
        return false;
    }
    if(startMemCost > stopMemCost) {
        fprintf(stderr, "startMemCost must be <= stopMemCost\n");
        return false;
    }
    if(stopMemCost > 30) {
        fprintf(stderr, "stopMemCost must be <= 30\n");
        return false;
    }
    if(timeCost > 30) {
        fprintf(stderr, "timeCost must be <= 30\n");
        return false;
    }
    if(multiplies > 8) {
        fprintf(stderr, "multiplies must be <= 8\n");
        return false;
    }
    if(parallelism == 0) {
        fprintf(stderr, "parallelism must be from 1 to 255\n");
        return false;
    }
    if(blockSize > (1 << 20)) {
        fprintf(stderr, "blockSize must be a power of 2 from 32 to 2^20\n");
        return false;
    }
    if(subBlockSize < 32 || subBlockSize > blockSize) {
        fprintf(stderr, "subBlockSize must be a power of 2 from 32 to blockSize.\n");
        return false;
    }
    while(!(blockSize & 1)) {
        blockSize >>= 1;
    }
    while(!(subBlockSize & 1)) {
        subBlockSize >>= 1;
    }
    if(blockSize != 1) {
        fprintf(stderr, "blockSize must be a power of 2 from 32 to 2^20\n");
        return false;
    }
    if(subBlockSize != 1) {
        fprintf(stderr, "subBlockSize must be a power of 2 from 32 to blockSize.\n");
        return false;
    }
    return true;
}

// A simple password hashing interface.
bool TwoCats_HashPassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
        uint32_t passwordSize, const uint8_t *salt, uint32_t saltSize, uint8_t memCost,
        bool clearPassword) {
    return TwoCats_HashPasswordFull(hashType, hash, password, passwordSize,
        salt, saltSize, memCost, 0, TWOCATS_PARALLELISM, clearPassword);
}

// The full password hashing interface.  
bool TwoCats_HashPasswordFull(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
        uint32_t passwordSize, const uint8_t *salt, uint32_t saltSize, uint8_t memCost,
        uint8_t timeCost, uint8_t parallelism, bool clearPassword) {

    uint8_t multiplies = 3; // Decent match for Intel Sandy Bridge through Haswell
    if(memCost <= 4) {
        multiplies = 1; // Assume it fits in L1 cache
    } else if(memCost < 10) {
        multiplies = 2; // Assume it fits in L2 or L3 cache
    }
    uint32_t blockSize = TWOCATS_BLOCKSIZE;
    uint32_t subBlockSize = TWOCATS_SUBBLOCKSIZE;
    uint64_t memSize = (uint64_t)1024 << memCost;
    while(blockSize >= 64 && memSize/(parallelism*blockSize) < TWOCATS_MINBLOCKS) {
        blockSize >>= 1;
    }
    if(subBlockSize > blockSize) {
        subBlockSize = blockSize;
    }
    while(parallelism > 1 && memSize/(parallelism*blockSize) < TWOCATS_MINBLOCKS) {
        parallelism--;
    }
    return TwoCats_HashPasswordExtended(hashType, hash, password, passwordSize, salt,
        saltSize, NULL, 0, memCost, memCost, timeCost, multiplies, TWOCATS_LANES,
        parallelism, TWOCATS_BLOCKSIZE, TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST,
        clearPassword, false);
}

// The extended password hashing interface.  
bool TwoCats_HashPasswordExtended(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
        uint32_t passwordSize, const uint8_t *salt, uint32_t saltSize, uint8_t *data,
        uint32_t dataSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint8_t multiplies, uint8_t lanes, uint8_t parallelism, uint32_t blockSize,
        uint32_t subBlocksize, uint8_t overwriteCost, bool clearPassword, bool clearData) {

    if(!TwoCats_ClientHashPassword(hashType, hash, password, passwordSize, salt,
            saltSize, data, dataSize, startMemCost, stopMemCost, timeCost, multiplies,
            lanes, parallelism, blockSize, subBlocksize, overwriteCost, clearPassword, clearData)) {
        return false;
    }
    return TwoCats_ServerHashPassword(hashType, hash);
}

// Update an existing password hash to a more difficult level of memory cost (garlic).
bool TwoCats_UpdatePassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t oldMemCost,
        uint8_t newMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t lanes,
        uint8_t parallelism, uint32_t blockSize, uint32_t subBlockSize) {

    TwoCats_H H;
    TwoCats_InitHash(&H, hashType);
    if(!verifyParameters(&H, oldMemCost, newMemCost, timeCost, multiplies, lanes,
            parallelism, blockSize, subBlockSize)) {
        return false;
    }
    uint32_t hash32[H.len];
    decodeLittleEndian(hash32, hash, H.size);
    if(!TwoCats(&H, hash32, oldMemCost, newMemCost, timeCost, multiplies, lanes,
            parallelism, blockSize, subBlockSize, 0)) {
        return false;
    }
    encodeLittleEndian(hash, hash32, H.size);
    return TwoCats_ServerHashPassword(hashType, hash);
}

// Client-side portion of work for server-relief mode.  Return true if there are no memory
// allocation errors.  The password and data are not cleared if there is an error.
bool TwoCats_ClientHashPassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
        uint32_t passwordSize, const uint8_t *salt, uint32_t saltSize, uint8_t *data,
        uint32_t dataSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint8_t multiplies, uint8_t lanes, uint8_t parallelism, uint32_t blockSize,
        uint32_t subBlockSize, uint8_t overwriteCost, bool clearPassword, bool clearData) {

    TwoCats_H H;
    TwoCats_InitHash(&H, hashType);
    if(!verifyParameters(&H, startMemCost, stopMemCost, timeCost, multiplies, lanes,
            parallelism, blockSize, subBlockSize)) {
        return false;
    }

    // Convert overwiteCost from relative to startMemCost to absolute
    if(overwriteCost >= startMemCost) {
        overwriteCost = 0;
    } else if(overwriteCost != 0) {
        overwriteCost = startMemCost - overwriteCost;
    }

    // Add all the inputs, other than stopMemCost
    uint32_t hash32[H.len];
    if(!H.Init(&H) || !H.UpdateUint32(&H, passwordSize) ||
            !H.UpdateUint32(&H, saltSize) || !H.UpdateUint32(&H, dataSize) ||
            !H.UpdateUint32(&H, blockSize) || !H.UpdateUint32(&H, subBlockSize) ||
            !H.Update(&H, &startMemCost, 1) || !H.Update(&H, &timeCost, 1) ||
            !H.Update(&H, &multiplies, 1) || !H.Update(&H, &lanes, 1) ||
            !H.Update(&H, &parallelism, 1) || !H.Update(&H, &overwriteCost, 1) ||
            !H.Update(&H, password, passwordSize) || !H.Update(&H, salt, saltSize) ||
            !H.Update(&H, data, dataSize) || !H.FinalUint32(&H, hash32)) {
        return false;
    }

    // Now clear the password and data if allowed
    if(clearPassword && passwordSize != 0) {
        secureZeroMemory(password, passwordSize);
    }
    if(clearData && dataSize != 0) {
        secureZeroMemory(data, dataSize);
    }

    if(!TwoCats(&H, hash32, startMemCost, stopMemCost, timeCost, multiplies,
            lanes, parallelism, blockSize, subBlockSize, overwriteCost)) {
        return false;
    }
    encodeLittleEndian(hash, hash32, H.size);
    secureZeroMemory(hash32, H.size);
    return true;
}

// Server portion of work for server-relief mode.
bool TwoCats_ServerHashPassword(TwoCats_HashType hashType, uint8_t *hash) {
    TwoCats_H H;
    TwoCats_InitHash(&H, hashType);
    return H.Init(&H) && H.Update(&H, hash, H.size) && H.Final(&H, hash);
}

// The SkinnyCat API.
bool SkinnyCat_HashPassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
        uint8_t passwordSize, const uint8_t *salt, uint8_t saltSize, uint8_t memCost,
        bool clearPassword) {
    uint32_t blockSize = TWOCATS_BLOCKSIZE;
    while(blockSize > 32 && ((uint64_t)1024 << memCost)/blockSize < TWOCATS_MINBLOCKS) {
        blockSize >>= 1;
    }
    printf("blockSize:%u\n", blockSize);
    return TwoCats_HashPasswordExtended(hashType, hash, password, passwordSize, salt, saltSize, NULL, 0,
        memCost, memCost, 0, 0, TWOCATS_LANES, 1, blockSize, blockSize, 0, clearPassword, false);
}

// This is the prototype required for the password hashing competition.
// t_cost is a multiplier on CPU work.  m_cost is garlic.
// If possible, call TwoCats_SimpleHashPassword instead so that the password can be cleared.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    if(outlen != 32) {
        fprintf(stderr, "Expected outlen == 32\n");
        return 1;
    }
    return !TwoCats_HashPasswordFull(TWOCATS_HASHTYPE, out, (uint8_t *)in, inlen,
        salt, saltlen, m_cost, t_cost, TWOCATS_PARALLELISM, false);
}

// Just measure the time for a given memCost and timeCost.  Return -1 if memory allocation fails.
static clock_t findRuntime(TwoCats_HashType hashType, uint8_t memCost, uint8_t timeCost,
        uint8_t multiplies, uint8_t lanes) {
    uint32_t keySize = TwoCats_GetHashTypeSize(hashType);
    uint8_t buf[keySize];
    clock_t start = clock();
    if(!TwoCats_HashPasswordExtended(hashType, buf, NULL, 0, NULL, 0, NULL, 0, memCost,
            memCost, timeCost, multiplies, lanes, TWOCATS_PARALLELISM, TWOCATS_BLOCKSIZE,
            TWOCATS_SUBBLOCKSIZE, 0, false, false)) {
        fprintf(stderr, "Memory hashing failed\n");
        return -1;
    }
    clock_t end = clock();
    return (end - start) * 1000 / CLOCKS_PER_SEC;
}

// Find a good memCost for a given time on this machine.  This just finds the largest
// memCost that runs in less than milliseconds ms.  Return 255 on failure to allocate memory.
static uint8_t findMemCost(TwoCats_HashType hashType, uint32_t milliseconds, uint32_t
        maxMem, clock_t *finalTime, uint8_t lanes) {
    // First, find a decent memCost
    uint8_t memCost = 0;
    clock_t runtime = findRuntime(hashType, 0, 0, 0, lanes);
    while(runtime < milliseconds && (1 << memCost) <= maxMem) {
        memCost++;
        if(runtime < milliseconds/8) {
            memCost++;
        }
        runtime = findRuntime(hashType, memCost, 0, 0, lanes);
        //printf("New findMemCost runtime: %u\n", runtime);
    }
    *finalTime = runtime;
    return memCost;
}

// Find parameter settings on this machine for a given desired runtime and maximum memory
// usage.  maxMem is in KiB.  Runtime with be typically +/- 50% and memory will be <= maxMem.
void TwoCats_FindCostParameters(TwoCats_HashType hashType, uint32_t milliseconds, uint32_t
        maxMem, uint8_t *memCost, uint8_t *timeCost, uint8_t *multiplies, uint8_t *lanes) {

// Lanes is simplest to pick.  If we have good custom code for it, use it.
#if defined(__AVX2__)
    *lanes = 8;
#elif defined(__SSE2__)
    *lanes = 4;
#else
    *lanes = 1;
#endif

    clock_t runtime;
    *memCost = findMemCost(hashType, milliseconds/8, maxMem/8, &runtime, *lanes);
    // Now increase timeCost until we see it beginning to work
    clock_t initialRuntime = findRuntime(hashType, *memCost, 0, 0, *lanes);
    clock_t prevRuntime;
    *timeCost = 0;
    do {
        *timeCost += 1;
        prevRuntime = runtime;
        runtime = findRuntime(hashType, *memCost, *timeCost, 0, *lanes);
        //printf("Increasing timeCost: %u\n", runtime);
    } while(runtime < 1.05*initialRuntime);
    *timeCost -= 1;
    initialRuntime = prevRuntime;

    *multiplies = 0;
    do {
        *multiplies += 1;
        runtime = findRuntime(hashType, *memCost, *timeCost, *multiplies, *lanes);
        //printf("New multiply runtime: %u\n", runtime);
    } while(runtime < 1.05*initialRuntime && *multiplies < 8);

    // Now scale up the memory
    while(runtime < milliseconds && (1 << *memCost) < maxMem) {
        //printf("Adding 1 to memCost, runtime:%u memCost:%u\n", runtime, *memCost);
        *memCost += 1;
        runtime *= 1.75;
    }

    // Increase timeCost if still needed
    while(runtime < milliseconds) {
        //printf("Adding 1 to timecost\n");
        *timeCost += 1;
        runtime *= 1.75;
    }
}
