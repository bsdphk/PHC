#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "twocats.h"

#define KEY_SIZE 32
#define SALT_SIZE 16

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: twocats-enc pasword file\n"
        "    This will create file.enc, encrypted with AES-256 in CBC mode.\n"
        "    Please use this as example code rather than a real encryption tool\n");
    exit(1);
}

// Read from /dev/urandom to find a salt.
static void genSalt(uint8_t *salt) {
    FILE *randFile = fopen("/dev/urandom", "r");
    if(randFile == NULL) {
        fprintf(stderr, "Unable to open random /dev/urandom\n");
        exit(1);
    }
    for(uint32_t i = 0; i < SALT_SIZE; i++) {
        salt[i] = getc(randFile);
    }
    fclose(randFile);
}

int main(int argc, char **argv) {
    if(argc != 3) {
        usage("Invalid number of arguments");
    }
    char *password = argv[1];
    char *inFileName = argv[2];
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];

    FILE *inFile = fopen(inFileName, "r");
    if(inFile == NULL) {
        fprintf(stderr, "Unable to open file %s\n", inFileName);
        return 1;
    }
    char outFileName[strlen(inFileName) + 4];
    strcpy(outFileName, inFileName);
    strcat(outFileName, ".enc");
    FILE *outFile = fopen(outFileName, "w");
    if(outFile == NULL) {
        fprintf(stderr, "Unable to open file %s for writing\n", outFileName);
        return 1;
    }

    // Find out how much memory to use to have 0.5 second of hashing.  Max out at 2GiB.
    // 1000 means 1000 milliseconds, and 20 means 2^21 KiB max memory == 2 GiB.
    uint8_t memCost, timeCost, multiplies, lanes;
    TwoCats_FindCostParameters(TWOCATS_BLAKE2S, 1000, 2*1024*1024, &memCost, &timeCost, &multiplies, &lanes);
    printf("Encrypting with memCost=%u timeCost=%u multiplies=%u lanes=%u\n", memCost, timeCost, multiplies, lanes);

    genSalt(salt);
    if(!TwoCats_HashPasswordExtended(TWOCATS_HASHTYPE, key, (uint8_t *)password, strlen(password),
            salt, SALT_SIZE, NULL, 0, memCost, memCost, timeCost, multiplies, lanes, TWOCATS_PARALLELISM,
            TWOCATS_BLOCKSIZE, TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Unable to hash password - memory allocation failed\n");
        return 1;
    }

    // Write header: salt, memCost, timeCost, lanes
    fwrite(salt, sizeof(uint8_t), SALT_SIZE, outFile);
    fwrite(&memCost, sizeof(uint8_t), 1, outFile);
    fwrite(&timeCost, sizeof(uint8_t), 1, outFile);
    fwrite(&multiplies, sizeof(uint8_t), 1, outFile);
    fwrite(&lanes, sizeof(uint8_t), 1, outFile);

    // Initialize encrpytion
    EVP_CIPHER_CTX ctx;
    uint8_t out[32]; /* at least one block longer than in[] */
    EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, salt);

    // Encrypt input stream to output stream
    int outlen;
    int c;
    while((c = getc(inFile)) != EOF) {
        uint8_t buf = c;
        EVP_EncryptUpdate(&ctx, out, &outlen, &buf, sizeof(uint8_t));
        if(outlen != 0) {
            fwrite(out, sizeof(uint8_t), outlen, outFile);
        }
    }

    // Finalize encryption
    EVP_EncryptFinal(&ctx, out, &outlen);
    if(outlen != 0) {
        fwrite(out, sizeof(uint8_t), outlen, outFile);
    }
    fclose(outFile);
    fclose(inFile);

    return 0;
}
