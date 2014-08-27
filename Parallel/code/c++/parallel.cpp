// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#include <assert.h>
#include <string.h>
#include "parallel.h"
#include "sha512.h"

#define HASH_LENGTH    Sha512::HASH_LENGTH

inline uint64_t calcLoopCount(uint32_t cost)
{
	// floor((cost & 1 ? 2 : 3) * 2 ** floor((cost - 1) / 2))
	// 1, 2, 3, 4, 6, 8, 12, 16, ...
	if (cost == 0)
	{
		return 1;
	}
	return ((uint64_t) ((cost & 1) ^ 3)) << ((cost - 1) >> 1);
}

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t key [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t tmp [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t work[HASH_LENGTH / sizeof(uint64_t)];
	uint64_t parallelLoops;
	uint64_t sequentialLoops;
	Sha512   sha512;

	if ((t_cost & 0xffff) > 106 || (t_cost >> 16) > 126 || outlen > HASH_LENGTH)
	{
		memset(out, 0, outlen);
		return 1;
	}

	// key = SHA512(SHA512(salt) || in)
	Sha512::hash(salt, saltlen, key);
	sha512.init();
	sha512.update(key, HASH_LENGTH);
	sha512.update(in,  inlen);
	sha512.finish(key);

	// Work
	parallelLoops = 3 * 5 * 128 * calcLoopCount(t_cost & 0xffff);
	sequentialLoops = calcLoopCount(t_cost >> 16);

	for (uint64_t i = 0; i < sequentialLoops; i++)
	{
		// Clear work
		memset(work, 0, HASH_LENGTH);

		for (uint64_t j = 0; j < parallelLoops; j++)
		{
			// work ^= SHA512(WRITE_BIG_ENDIAN_64(i) || WRITE_BIG_ENDIAN_64(j) || key)
			uint64_t tmpI = WRITE_BIG_ENDIAN_64(i);
			uint64_t tmpJ = WRITE_BIG_ENDIAN_64(j);

			sha512.init();
			sha512.update(&tmpI, sizeof(tmpI));
			sha512.update(&tmpJ, sizeof(tmpJ));
			sha512.update(key,   HASH_LENGTH);
			sha512.finish(tmp);
			for (unsigned int k = 0; k < HASH_LENGTH / sizeof(uint64_t); k++)
			{
				work[k] ^= tmp[k];
			}
		}

		// Finish
		// key = truncate(SHA512(SHA512(work || key)), outlen) || zeros(HASH_LENGTH - outlen)
		sha512.init();
		sha512.update(work, HASH_LENGTH);
		sha512.update(key,  HASH_LENGTH);
		sha512.finish(key);
		Sha512::hash(key, HASH_LENGTH, key, outlen);
		memset(((uint8_t*) key) + outlen, 0, HASH_LENGTH - outlen);
	}

	// Finish
	// out = key
	memcpy(out, key, outlen);

	// Clean up
	// TODO: find a secure wipe function
	memset(key,  0, sizeof(key));
	memset(work, 0, sizeof(key));
	memset(tmp,  0, sizeof(key));
	return 0;
}

int parallelKdf(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t key [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t tmp [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t work[HASH_LENGTH / sizeof(uint64_t)] = {0};
	uint64_t parallelLoops;
	Sha512   sha512;

	if (t_cost > 106 || outlen > HASH_LENGTH)
	{
		memset(out, 0, outlen);
		return 1;
	}

	// key = SHA512(SHA512(salt) || in)
	Sha512::hash(salt, saltlen, key);
	sha512.init();
	sha512.update(key, HASH_LENGTH);
	sha512.update(in,  inlen);
	sha512.finish(key);

	// Work
	parallelLoops = 3 * 5 * 128 * calcLoopCount(t_cost & 0xffff);
	for (uint64_t i = 0; i < parallelLoops; i++)
	{
		// work ^= SHA512(WRITE_BIG_ENDIAN_64(i) || key)
		uint64_t tmpI = WRITE_BIG_ENDIAN_64(i);

		sha512.init();
		sha512.update(&tmpI, sizeof(tmpI));
		sha512.update(key,   HASH_LENGTH);
		sha512.finish(tmp);
		for (unsigned int j = 0; j < HASH_LENGTH / sizeof(uint64_t); j++)
		{
			work[j] ^= tmp[j];
		}
	}

	// Finish
	// key = truncate(SHA512(SHA512(work || key)), outlen) || zeros(HASH_LENGTH - outlen)
	for (int32_t i = 0, left = (int32_t) outlen; left > 0; left -= HASH_LENGTH, i++)
	{
		uint64_t tmpI = WRITE_BIG_ENDIAN_64(i);

		// out = out || SHA512(WRITE_BIG_ENDIAN_64(i) || work || in)
		sha512.init();
		sha512.update(&tmpI, sizeof(tmpI));
		sha512.update(work,  HASH_LENGTH);
		sha512.update(in,    inlen);
		sha512.finish(out,   outlen);
		out = ((uint8_t*) out) + HASH_LENGTH;
	}

	// Clean up
	// TODO: find a secure wipe function
	memset(key,  0, sizeof(key));
	memset(work, 0, sizeof(key));
	memset(tmp,  0, sizeof(key));
	return 0;
}
