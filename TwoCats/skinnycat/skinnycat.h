/*
   SkinnyCat C API header file

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright and
   related and neighboring rights to this software to the public domain worldwide. This
   software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with this
   software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <stdbool.h>

/*
    This is the SkinnyCat password hashing scheme, which is a simple subset of SkinnyCat.
    More advanced users who want control over both runtime and memory hashing size should
    use TwoCats.
*/

// These are the primitive hash functions that can be plugged into SkinnyCat.
typedef enum {
    SKINNYCAT_BLAKE2S,
    SKINNYCAT_SHA256
} SkinnyCat_HashType;

// On success, a 32-byte password hash is written, and true is returned.  Otherwise false
// is returned, and hash and password are unchanged.  Each increment of memCost doubles
// difficulty.  The memory hashed = 2^memCost KiB.  If clearPassword is set, the password
// is set to 0's early during the hashing.
bool SkinnyCat_HashPassword(SkinnyCat_HashType hashType, uint8_t hash[32],
                           uint8_t *password,   uint8_t passwordSize,
                           const uint8_t *salt, uint8_t saltSize,
                           uint8_t memCost,     bool clearPassword);

// This is the prototype required for the password hashing competition.  It uses Blake2s.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);
