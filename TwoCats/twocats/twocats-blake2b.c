#include "twocats-internal.h"

#if defined(__AVX2__) || defined(__SSE2__)
#include "../blake2-sse/blake2b.c"
#else
#include "../blake2-ref/blake2b-ref.c"
#endif

// Initilized the state.
static bool init(TwoCats_H *H) {
    return !blake2b_init(&(H->c.blake2bState), 64);
}

// Update the state.
static bool update(TwoCats_H *H, const uint8_t *data, uint32_t dataSize) {
    return !blake2b_update(&(H->c.blake2bState), data, dataSize);
}

// Finalize and write out the result.
static bool final(TwoCats_H *H, uint8_t *hash) {
    return !blake2b_final(&(H->c.blake2bState), hash, 64);
}

// Initialize the hashing object for Blake2b hashing.
void TwoCats_InitBlake2b(TwoCats_H *H) {
    H->name = "blake2b";
    H->size = 64;
    H->Init = init;
    H->Update = update;
    H->Final = final;
}

