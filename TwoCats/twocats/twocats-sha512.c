#include "twocats-internal.h"

// Initilized the state.
static bool init(TwoCats_H *H) {
    return SHA512_Init(&(H->c.sha512State));
}

// Update the state.
static bool update(TwoCats_H *H, const uint8_t *data, uint32_t dataSize) {
    return SHA512_Update(&(H->c.sha512State), data, dataSize);
}

// Finalize and write out the result.
static bool final(TwoCats_H *H, uint8_t *hash) {
    return SHA512_Final(hash, &(H->c.sha512State));
}

// Initialize the hashing object for sha512 hashing.
void TwoCats_InitSHA512(TwoCats_H *H) {
    H->name = "sha512";
    H->size = 64;
    H->Init = init;
    H->Update = update;
    H->Final = final;
}

