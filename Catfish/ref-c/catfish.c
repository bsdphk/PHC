#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "KeccakSponge.h"

#include "catfish.h"
#include "pkhash_1024.h"

#define BITLEN 1024
#define BYTELEN 128

static void keccak_wrapper(const uint8_t *in, const size_t inlen, uint8_t *out, const size_t outlen) {
    Keccak_SpongeInstance sponge;
    Keccak_SpongeInitialize(&sponge, 1024, 576);

    Keccak_SpongeAbsorb(&sponge, (unsigned char*)in, inlen);
    Keccak_SpongeSqueeze(&sponge, out, outlen);
}

static void H(uint8_t *state, size_t len) {
    uint8_t temp[BYTELEN];

    keccak_wrapper(state, len, temp, BYTELEN);
    pkhash_slow(temp, BYTELEN, state);
}

static void xor_number(uint64_t num, uint8_t *str) {
    while (num > 0) {
        *str ^= num & 0xFF;
        num >>= 8;
        str++;
    }
}

static void xor_string(const uint8_t *src, uint8_t *dst) {
    int i;
    for (i = 0; i < BYTELEN; i++) {
        dst[i] ^= src[i];
    }
}

static uint64_t str2int(const uint8_t *str) {
    uint64_t res = 0;  // 64 bits should be enough
    int i;

    for (i = 0; i < 8; i++) {
        res += str[i] << (8 * i);
    }

    return res;
}


int catfish(
        uint8_t *tag, size_t taglen,  // in byte, not bit
        const uint8_t *pass, size_t passlen,  // in byte
        const uint8_t *salt, size_t saltlen,  // in byte
        unsigned int tcost, unsigned int mcost)
{
    if (taglen != 32)  // 256 bits
        return 1;
    if (saltlen != 16)  // 128 bits
        return 2;
    if (tcost < 1 || mcost < 1)
        return 3;

    int i, j;
    uint64_t k;
    uint8_t x[128 / 8 + 128 / 8 + 128] = {0};

    // padding
    memcpy(x, salt, 16);
    xor_number((uint64_t)(passlen * 8), x + 16);
    memcpy(x + 32, pass, passlen);

    /*
    for (int z = 0; z < 128 + 16 + 16; z++) {
        printf("%02x", x[z]);
    }
    printf("\n");
    */

    uint8_t v[mcost][BYTELEN];

    uint64_t ctr = 0;
    for (i = 0; i < tcost; i++) {
        if (i == 0) {
            H(x, 16 + 16 + 128);
        } else {
            H(x, BYTELEN);
        }
        /*
        for (int z = 0; z < 128; z++) {
            printf("%02x", x[z]);
        }
        printf("\n");
        */

        for (j = 0; j < mcost; j++) {
            memcpy(v[j], x, BYTELEN);
            ctr++;
            xor_number(ctr, x);
            H(x, BYTELEN);
        }
        for (j = 0; j < mcost; j++) {
            k = str2int(x) % mcost;
            xor_string(v[k], x);
            ctr++;
            xor_number(ctr, x);
            H(x, BYTELEN);
        }

        ctr++;
    }

    /*
    for (int z = 0; z < 128; z++) {
        printf("%02x", x[z]);
    }
    printf("\n");
    */

    xor_number(ctr, x);
    keccak_wrapper(x, BYTELEN, tag, taglen);

    return 0;
}
