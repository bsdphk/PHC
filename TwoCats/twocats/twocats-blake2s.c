#include "twocats-internal.h"

#if defined(__AVX2__) || defined(__SSE2__)
#include "../blake2-sse/blake2s.c"
#else
#include "../blake2-ref/blake2s-ref.c"
#endif

// Initilized the state.
static bool init(TwoCats_H *H) {
    return !blake2s_init(&(H->c.blake2sState), 32);
}

// Update the state.
static bool update(TwoCats_H *H, const uint8_t *data, uint32_t dataSize) {
    return !blake2s_update(&(H->c.blake2sState), data, dataSize);
}

// Finalize and write out the result.
static bool final(TwoCats_H *H, uint8_t *hash) {
    return !blake2s_final(&(H->c.blake2sState), hash, 32);
}

// Initialize the hashing object for Blake2s hashing.
void TwoCats_InitBlake2s(TwoCats_H *H) {
    H->name = "blake2s";
    H->size = 32;
    H->Init = init;
    H->Update = update;
    H->Final = final;
}

