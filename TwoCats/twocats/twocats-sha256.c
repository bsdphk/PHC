#include "twocats-internal.h"

// Initilized the state.
static bool init(TwoCats_H *H) {
    return SHA256_Init(&(H->c.sha256State));
}

// Update the state.
static bool update(TwoCats_H *H, const uint8_t *data, uint32_t dataSize) {
    return SHA256_Update(&(H->c.sha256State), data, dataSize);
}

// Finalize and write out the result.
static bool final(TwoCats_H *H, uint8_t *hash) {
    return SHA256_Final(hash, &(H->c.sha256State));
}

// Initialize the hashing object for sha256 hashing.
void TwoCats_InitSHA256(TwoCats_H *H) {
    H->name = "sha256";
    H->size = 32;
    H->Init = init;
    H->Update = update;
    H->Final = final;
}

