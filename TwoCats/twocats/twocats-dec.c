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
    fprintf(stderr, "\nUsage: twocats-dec pasword file.enc\n"
        "    This will decrypt file to file.enc\n"
        "    Please use this as example code rather than a real encryption tool\n");
    exit(1);
}

int main(int argc, char **argv) {
    if(argc != 3) {
        usage("Invalid number of arguments");
    }
    char *password = argv[1];
    char *inFileName = argv[2];
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];

    if(strlen(inFileName) < 5 || strcmp(inFileName + strlen(inFileName) - 4, ".enc")) {
        fprintf(stderr, "Input file must end in .enc\n");
        return 1;
    }
    FILE *inFile = fopen(inFileName, "r");
    if(inFile == NULL) {
        fprintf(stderr, "Unable to open file %s\n", inFileName);
        return 1;
    }
    char outFileName[strlen(inFileName)];
    strcpy(outFileName, inFileName);
    outFileName[strlen(inFileName) - 4] = '\0';
    FILE *outFile = fopen(outFileName, "w");
    if(outFile == NULL) {
        fprintf(stderr, "Unable to open file %s for writing\n", outFileName);
        return 1;
    }

    // Read the file header: salt, key, memCost, timeCost
    uint8_t timeCost, memCost, multiplies, lanes;
    if(fread(salt, sizeof(uint8_t), SALT_SIZE, inFile) != SALT_SIZE ||
            fread(&memCost, sizeof(uint8_t), 1, inFile) != 1 ||
            fread(&timeCost, sizeof(uint8_t), 1, inFile) != 1 ||
            fread(&multiplies, sizeof(uint8_t), 1, inFile) != 1 ||
            fread(&lanes, sizeof(uint8_t), 1, inFile) != 1) {
        fprintf(stderr, "Input file too short\n");
        return 1;
    }

    if(!TwoCats_HashPasswordExtended(TWOCATS_HASHTYPE, key, (uint8_t *)password, strlen(password),
            salt, SALT_SIZE, NULL, 0, memCost, memCost, timeCost, multiplies, lanes, TWOCATS_PARALLELISM,
            TWOCATS_BLOCKSIZE, TWOCATS_SUBBLOCKSIZE, TWOCATS_OVERWRITECOST, false, false)) {
        fprintf(stderr, "Unable to hash password - memory allocation failed\n");
        return 1;
    }

    // Initialize encrpytion
    EVP_CIPHER_CTX ctx;
    uint8_t out[32]; /* at least one block longer than in[] */
    EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, salt);

    // Encrypt input stream to output stream
    int outlen;
    int c;
    while((c = getc(inFile)) != EOF) {
        uint8_t buf = c;
        EVP_DecryptUpdate(&ctx, out, &outlen, &buf, sizeof(uint8_t));
        if(outlen != 0) {
            fwrite(out, sizeof(uint8_t), outlen, outFile);
        }
    }

    // Finalize encryption
    EVP_DecryptFinal(&ctx, out, &outlen);
    if(outlen != 0) {
        fwrite(out, sizeof(uint8_t), outlen, outFile);
    }
    fclose(outFile);
    fclose(inFile);

    return 0;
}
