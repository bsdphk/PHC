#include <openssl/sha.h>

#include "catena.h"
#include "hash.h"

/***************************************************/

inline void __Hash1(const uint8_t *input, const uint32_t inputlen,
		      uint8_t hash[H_LEN])
{
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, input, inputlen);
  SHA512_Final(hash, &ctx);
}

/***************************************************/

inline void __Hash2(const uint8_t *i1, const uint8_t i1len,
		    const uint8_t *i2, const uint8_t i2len,
		    uint8_t hash[H_LEN])
{
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, i1, i1len);
  SHA512_Update(&ctx, i2, i2len);
  SHA512_Final(hash, &ctx);
}



/***************************************************/

inline void __Hash3(const uint8_t *i1, const uint8_t i1len,
		    const uint8_t *i2, const uint8_t i2len,
		    const uint8_t *i3, const uint8_t i3len,
		    uint8_t hash[H_LEN])
{

  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, i1, i1len);
  SHA512_Update(&ctx, i2, i2len);
  SHA512_Update(&ctx, i3, i3len);
  SHA512_Final(hash, &ctx);
}

/***************************************************/

inline void __Hash4(const uint8_t *i1, const uint8_t i1len,
		    const uint8_t *i2, const uint8_t i2len,
		    const uint8_t *i3, const uint8_t i3len,
		     const uint8_t *i4, const uint8_t i4len,
		    uint8_t hash[H_LEN])
{
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, i1, i1len);
  SHA512_Update(&ctx, i2, i2len);
  SHA512_Update(&ctx, i3, i3len);
  SHA512_Update(&ctx, i4, i4len);
  SHA512_Final(hash, &ctx);
}


/***************************************************/

inline void __Hash5(const uint8_t *i1, const uint8_t i1len,
		    const uint8_t *i2, const uint8_t i2len,
		    const uint8_t *i3, const uint8_t i3len,
		    const uint8_t *i4, const uint8_t i4len,
		    const uint8_t *i5, const uint8_t i5len,
		    uint8_t hash[H_LEN])
{
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, i1, i1len);
  SHA512_Update(&ctx, i2, i2len);
  SHA512_Update(&ctx, i3, i3len);
  SHA512_Update(&ctx, i4, i4len);
  SHA512_Update(&ctx, i5, i5len);
  SHA512_Final(hash, &ctx);
}


/***************************************************/
