/*
   TwoCats C API header file

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
    This is the TwoCats password hashing scheme.  Most users will find the simple
    TwoCats_HashPassword interface sufficient.  More advanced users who want control over
    both runtime and memory hashing size should use TwoCats_HashPasswordFull.  If you
    know what you are doing and want bare metal control, use TwoCats_HashPasswordExtended.

    For all of these functions, these are the restrictions on sizes:

    hash is 32 or 64 bytes, depending on the selelected hashType
    memCost <= 30
    timeCost <= 30
    multiplies <= 8
    1 <= prallelism <= 255
    startMemCost <= stopMemCost <= 30
    oldMemCost < newMemCost <= 30
    32 <= subBlockSize <= blockSize <= 2^20 -- both must be powers of 2
    1 <= lanes <= hash size/4 (for example, 8 for SHA256)

    NULL values and 0 lengths are legal for all variable sized inputs.  Lengths for NULL
    values must be 0.

    Preferably, passwords and any other secret data are passed in fixed sized buffers.
    This insures that SHA256 can not leak length information.

    Preferably clearPassword is set to true so that the password can be overwritten
    with 0's at the beginning of hashing rather than by the user afterward.
*/

// These are the primitive hash functions that can be plugged into TwoCats.  To add
// another, add it's type here, declare it's init function in twocats-internal.h, copy
// twocats-sha256.c to twocats-<yourhash>.c and edit it.  Finally, modify TwoCats_InitH in
// twocats-common.c to call your initialization function.
typedef enum {
    TWOCATS_BLAKE2S,
    TWOCATS_BLAKE2B,
    TWOCATS_SHA256,
    TWOCATS_SHA512,
    TWOCATS_NONE
} TwoCats_HashType;

// This has to be updated when we add a hash type
#define TWOCATS_HASHTYPES 4

char *TwoCats_GetHashTypeName(TwoCats_HashType hashType);
TwoCats_HashType TwoCats_FindHashType(char *name);
uint8_t TwoCats_GetHashTypeSize(TwoCats_HashType hashType);

// The default password hashing interface.  On success, a hashSize byte password hash is
// written, and true is returned.  Otherwise false is returned, and hash and password are
// unchanged.  Each increment of memCost doubles difficulty.  The memory hashed =
// 2^memCost KiB.  If clearPassword is set, the password is set to 0's early during
// the hashing.

bool TwoCats_HashPassword( TwoCats_HashType hashType, uint8_t *hash,
                           uint8_t *password,   uint32_t passwordSize,
                           const uint8_t *salt, uint32_t saltSize,
                           uint8_t memCost,     bool clearPassword);

// The SkinnyCat API is a TwoCat compliant KISS password hashing scheme.  It differs from
// TwoCats_HashPassword by disabling many of the more advanced features of TwoCats when
// calling the extended TwoCats interface.  On success, a 32 or 64 byte (depending on
// hashType) hash value is written, and true is returned.  The point of SkinnyCat is to
// simplify creation of compatible implementations.

bool SkinnyCat_HashPassword( TwoCats_HashType hashType, uint8_t *hash,
                           uint8_t *password,   uint8_t passwordSize,
                           const uint8_t *salt, uint8_t saltSize,
                           uint8_t memCost,     bool clearPassword);

// The full password hashing interface.  On success, true is returned, otherwise false.
// Memory hashed = 2^memCost KiB.  Repetitions of hashing = 2^timeCost.  Number of
// threads used = parallelism.  The password is set to 0's early during the
// hashing if clearPassword is set.

bool TwoCats_HashPasswordFull( TwoCats_HashType hashType, uint8_t *hash,
                               uint8_t *password,   uint32_t passwordSize,
                               const uint8_t *salt, uint32_t saltSize,
                               uint8_t memCost,     uint8_t timeCost,
                               uint8_t parallelism, bool clearPassword);


/* These values make reasonable defaults when using the extended interface */

#define TWOCATS_MEMCOST 20 // 1 GiB
#define TWOCATS_PARALLELISM 2
#define TWOCATS_BLOCKSIZE 16384
#define TWOCATS_SUBBLOCKSIZE 64
#define TWOCATS_TIMECOST 0
#define TWOCATS_MULTIPLIES 2
#define TWOCATS_HASHTYPE TWOCATS_BLAKE2S
#define TWOCATS_LANES 8
#define TWOCATS_OVERWRITECOST 6

/*
   This is the extended password hashing interface for those who know what they are doing.
   Consider running twocats-guessparams to find reasonalbe default values for a given
   memory cost for your specific machine.

   Data can be any application specific data, such as a secondary key or application name,
   or a concatenation of various data.

   startMemCost is normally equal to stopMemCost, unless a password hash has been
   strengthened using TwoCats_UpdatePassword.
   
   stopMemCost is the main memory hashing difficulty parameter, which causes 2^stopMemCost
   KiB of memory to be hashed.  Each increment doubles memory and difficulty.
   
   timeCost causes the inner loop to repeat 2^timeCost times, repeatedly hashing blocks
   that most likely fit in on-chip cache.  It can be used to increase runtime for a given
   memory size, and to reduce DRAM bandwidth while increasing cache bandwidth.  For memory
   sizes large enough to require external DRAM, it is ideally it is set as high as
   possible without increasing runtime significantly. For memory sizes that fit in on-chip
   cache, timeCost needs to be set high enough to provide the desired security, which is
   aproximately runtime*memory.

   multiplies is used to force attackers to run each guess as long as you do.  It should
   be set as high as possible without increasing runtime significantly.  3 is a reasonable
   default for hashing memory sizes larger than the CPU cache size, 2 is reasonable for
   L2/L3 cache sizes, and 1 is good for L1 cache sizes, or when timeCost is set high
   enough to cause the runtime to increase significantly.  For CPUs without hardware
   multiplication or on-chip data cache, multiplies should be set to 0.

   lanes is used to make use of SIMD parallelism available on the CPU, such as SSE2 and
   AVX2.  Older CPUs without any SIMD unit should set lanes to 1.  Sandy Bridge and Ivy
   Bridge Intel processors run best with lanes set to 4.  Haswell runs best with lanes set
   to 8.

   parallelism is the number of threads used in parallel to hash the password.  A
   reasonable number is half the CPU cores you expect to have idle at any time, but it
   must be at least 1.  Each thread hashes memory so fast, you likely will maximize memory
   bandwidth with only 2 threads.  Higher values can be used on multi-CPU servers with
   more than two memory banks to increase password security.

   startMemCost - overwriteCost is the cost used to throw away memory early, to provide
   some protection in case memory is leaked to an attacker.  The default of 6 causes about
   3% of the early memory to be overwritten.  Setting it to 0 will disable this feature.

   If clearPassword is true, the password is set to 0's  early in hashing, and if
   clearData is set, the data input is set to 0's early in hashing.
*/

bool TwoCats_HashPasswordExtended( TwoCats_HashType hashType, uint8_t *hash,
                                   uint8_t *password,     uint32_t passwordSize,
                                   const uint8_t *salt,   uint32_t saltSize,
                                   uint8_t *data,         uint32_t dataSize,
                                   uint8_t startMemCost,  uint8_t stopMemCost,
                                   uint8_t timeCost,      uint8_t multiplies,
                                   uint8_t lanes,         uint8_t parallelism,
                                   uint32_t blockSize,    uint32_t subBlockSize,
                                   uint8_t overwriteCost, bool clearPassword,
                                   bool clearData);

// Update an existing password hash to a more difficult level of memCost.
bool TwoCats_UpdatePassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t oldMemCost,
    uint8_t newMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t lanes, uint8_t parallelism,
    uint32_t blockSize, uint32_t subBlockSize);

// Client-side portion of work for server-relief mode.
bool TwoCats_ClientHashPassword(TwoCats_HashType hashType, uint8_t *hash, uint8_t *password,
    uint32_t passwordSize, const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize,
    uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost, uint8_t multiplies,
    uint8_t lanes, uint8_t parallelism, uint32_t blockSize, uint32_t subBlockSize, uint8_t overwriteCost,
    bool clearPassword, bool clearData);

// Server portion of work for server-relief mode.
bool TwoCats_ServerHashPassword(TwoCats_HashType hashType, uint8_t *hash);

// Find parameter settings on this machine for a given desired runtime and maximum memory
// usage.  maxMem is in KiB.  Runtime with be typically +/- 50% and memory will be <= maxMem.
void TwoCats_FindCostParameters(TwoCats_HashType hashType, uint32_t milliSeconds, uint32_t maxMem,
    uint8_t *memCost, uint8_t *timeCost, uint8_t *multplies, uint8_t *lanes);

// This is the prototype required for the password hashing competition.  It uses Blake2s.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

void TwoCats_PrintHex(char *message, uint8_t *x, int len);
