// I, Bill Cox, initially copied this file from Catena's src/catena_test_vectors.c in
// 2014, and modified it to call TwoCats.  It was written by the Catena team and slightly
// changed by me.  It therefore falls under Catena's MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "twocats-internal.h"

#define TEST_MEMCOST 10

/*******************************************************************/

void test_output(TwoCats_HashType hashType,
                 uint8_t *pwd,   uint32_t pwdlen,
                 uint8_t *salt,  uint32_t saltlen,
                 uint8_t *data,  uint32_t datalen,
                 uint8_t memCost, uint8_t timeCost,
                 uint8_t multiplies, uint8_t lanes,
                 uint8_t parallelism)
{
    uint32_t hashlen = TwoCats_GetHashTypeSize(hashType);
    uint8_t hash[hashlen];

    TwoCats_PrintHex("Password: ",pwd, pwdlen);
    TwoCats_PrintHex("Salt: ",salt, saltlen);
    TwoCats_PrintHex("Associated data:", data, datalen);
    printf("memCost:%u timeCost:%u multiplies:%u lanes:%u parallelism:%u\n", memCost,
        timeCost, multiplies, lanes, parallelism);

    if(!TwoCats_HashPasswordExtended(hashType, hash, pwd, pwdlen, salt, saltlen, data,
            datalen, memCost, memCost, timeCost, multiplies, lanes, parallelism, TWOCATS_BLOCKSIZE,
            TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }

    TwoCats_PrintHex("\nOutput: ", hash, hashlen);
    printf("\n");
}

/*******************************************************************/

void PHC_test(TwoCats_HashType hashType) {

    int i;
    TwoCats_H H;
    TwoCats_InitHash(&H, hashType); // To gain access to length

    printf("****************************************** Test passwords\n");
    for(i=0; i < 256; i++) {
        test_output(hashType, (uint8_t *) &i, 1, NULL, 0, NULL, 0, TEST_MEMCOST, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test salt\n");
    for(i=0; i < 256; i++) {
        test_output(hashType, NULL, 0, (uint8_t *)&i, 1, NULL, 0, TEST_MEMCOST, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test data\n");
    for(i=0; i < 256; i++) {
        test_output(hashType, NULL, 0, NULL, 0, (uint8_t *)&i, 1, TEST_MEMCOST, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test memCost\n");
    for(i=0; i < TEST_MEMCOST; i++) {
        test_output(hashType, NULL, 0, NULL, 0, NULL, 0, i, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test timeCost\n");
    for(i=0; i < 12; i++) {
        test_output(hashType, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, i, TWOCATS_MULTIPLIES,
            TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test multiplies\n");
    for(i=0; i <= 8; i++) {
        test_output(hashType, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TWOCATS_TIMECOST, i,
            TWOCATS_LANES, TWOCATS_PARALLELISM);
    }
    printf("****************************************** Test parallelism\n");
    for(i=1; i < 10; i++) {
        test_output(hashType, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, TWOCATS_LANES, i);
    }
    printf("****************************************** Test lanes\n");
    for(i=1; i <= H.len; i <<= 1) {
        test_output(hashType, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TWOCATS_TIMECOST,
            TWOCATS_MULTIPLIES, i, TWOCATS_PARALLELISM);
    }
}

void verifyPasswordUpdate(TwoCats_HashType hashType) {

    uint32_t keySize = TwoCats_GetHashTypeSize(hashType);
    uint8_t hash1[keySize], hash2[keySize];
    if(!TwoCats_HashPasswordExtended(hashType, hash1, (uint8_t *)"password", 8,
            (uint8_t *)"salt", 4, NULL, 0, 0, TEST_MEMCOST, TWOCATS_TIMECOST, TWOCATS_MULTIPLIES,
            TWOCATS_LANES, TWOCATS_PARALLELISM, TWOCATS_BLOCKSIZE, TWOCATS_SUBBLOCKSIZE,
            TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    for(uint8_t memCost = 0; memCost < TEST_MEMCOST; memCost++) {
        if(!TwoCats_HashPasswordExtended(hashType, hash2, (uint8_t *)"password", 8,
                (uint8_t *)"salt", 4, NULL, 0, 0, memCost, TWOCATS_TIMECOST, TWOCATS_MULTIPLIES,
                TWOCATS_LANES, TWOCATS_PARALLELISM, TWOCATS_BLOCKSIZE,
                TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(!TwoCats_UpdatePassword(hashType, hash2, memCost + 1,
                TEST_MEMCOST, TWOCATS_TIMECOST, TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM,
                TWOCATS_BLOCKSIZE, TWOCATS_SUBBLOCKSIZE)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(memcmp(hash1, hash2, keySize)) {
            fprintf(stderr, "Password update got wrong answer!\n");
            exit(1);
        }
    }
}

void verifyClientServer(TwoCats_HashType hashType) {

    uint32_t keySize = TwoCats_GetHashTypeSize(hashType);
    uint8_t hash1[keySize];
    if(!TwoCats_ClientHashPassword(hashType, hash1, (uint8_t *)"password", 8,
            (uint8_t *)"salt", 4, (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST,
            TWOCATS_TIMECOST, TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM, TWOCATS_BLOCKSIZE,
            TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    TwoCats_ServerHashPassword(hashType, hash1);
    uint8_t hash2[keySize];
    if(!TwoCats_HashPasswordExtended(hashType, hash2, (uint8_t *)"password", 8,
            (uint8_t *)"salt", 4, (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST,
            TWOCATS_TIMECOST, TWOCATS_MULTIPLIES, TWOCATS_LANES, TWOCATS_PARALLELISM, TWOCATS_BLOCKSIZE,
            TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    if(memcmp(hash1, hash2, keySize)) {
        fprintf(stderr, "Password client/server got wrong answer!\n");
        exit(1);
    }
}

/*******************************************************************/

int main()
{
    for(uint32_t hashType = 0; hashType < TWOCATS_NONE; hashType++) {
        printf("****************************************** Testing hash type %s\n", TwoCats_GetHashTypeName(hashType));
        verifyPasswordUpdate(hashType);
        verifyClientServer(hashType);
        PHC_test(hashType);
    }
    return 0;
}
