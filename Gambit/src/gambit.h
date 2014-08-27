#ifndef GAMBIT_H_a5375c8c87ed67d2
#define GAMBIT_H_a5375c8c87ed67d2

/* DISCLAIMER
 * This is NOT a reference implementation!
 * This is a quick and dirty implementation provided to clarify any potential
 * ambiguities or unclear points in the documentation.
 * The software is not thoroughly tested, and not at all tested on platforms
 * other than Intel x86, Windows OS, and CodeBlocks/GNU compiler.
 * You can find the actual documentation at
 * http://docs.google.com/document/d/18R-qEAmL9WWh5zhGeBlvI7C6ikBAz6TF7MEtfPJK7m0
 *
 * This implementation uses Keccak[1600] with c=256 and 512. It does not support
 * the Trans option.
 */

#include <cstddef>

// PHC required intf
extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const
        void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);


namespace gambit
{
    typedef uint8_t salt [16];

    typedef uint8_t seed256 [32];
    typedef uint8_t dkid256 [168];

    void gambit256(const salt &salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   dkid256 dkid, void *key, int key_len);
    void gambit256(const salt salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   seed256 seed);
    void gambit256(const seed256 &seed,
                   dkid256 dkid, void *key, int key_len);

    typedef uint8_t seed512 [64];
    typedef uint8_t dkid512 [136];

    void gambit512(const salt &salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   dkid512 dkid, void *key, int key_len);
    void gambit512(const salt salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   seed512 seed);
    void gambit512(const seed512 &seed,
                   dkid512 dkid, void *key, int key_len);
}

#endif
