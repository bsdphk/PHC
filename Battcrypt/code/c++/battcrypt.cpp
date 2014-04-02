// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#include <assert.h>
#include <string.h>
#include "battcrypt.h"
#include "sha512.h"
#include "blowfish.h"

#define DATA_SIZE      512   // 2 KiB
#define DATA_BF_BLOCKS (DATA_SIZE / 2)
#define HASH_LENGTH    Sha512::HASH_LENGTH

// My assumptions for this code:
// HASH_LENGTH % sizeof(uint64_t)               == 0
// (sizeof(uint32_t) * DATA_SIZE) % HASH_LENGTH == 0
// DATA_SIZE % 2                                == 0
//  defined(ARC_32) && sizeof(size_t) == sizeof(uint32_t)
// !defined(ARC_32) && sizeof(size_t) == sizeof(uint64_t)

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	Sha512    sha512;
	uint32_t  data[DATA_SIZE];
	Blowfish  blowfish;
	uint64_t  key[HASH_LENGTH / sizeof(uint64_t)];
	uint64_t  upgradeLoops = 1;
	uint64_t  loops;
	size_t    memSize      = ((size_t) 4) <<  m_cost;
	size_t    memMask      = memSize - 1;
	uint32_t *mem;
	uint32_t *p;
	uint32_t *q;

	assert(HASH_LENGTH % sizeof(uint64_t) == 0);
	assert((sizeof(uint32_t) * DATA_SIZE) % HASH_LENGTH == 0);
	assert(DATA_SIZE % 2 == 0);
#ifdef ARC_32
	assert(sizeof(memSize) >= sizeof(uint32_t));
	if (m_cost > 18 || (t_cost & 0xffff) > 62 || (t_cost >> 16) > 63 || outlen > HASH_LENGTH)
	{
		return 1;
	}
#else
	assert(sizeof(memSize) >= sizeof(uint64_t));
	if (m_cost > 50 || (t_cost & 0xffff) > 62 || (t_cost >> 16) > 63 || outlen > HASH_LENGTH)
	{
		return 1;
	}
#endif

	// upgradeLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
	unsigned int tmp = t_cost >> 16;
	if (tmp != 0)
	{
		upgradeLoops = (uint64_t) (3 - (tmp & 1)) << ((tmp - 1) >> 1);
	}
	// loops = 2, 3, 4, 6, 8, 12, 16, ...
	tmp = t_cost & 0xffff;
	loops = (uint64_t) ((tmp & 1) + 2) << (tmp >> 1);

	// key = SHA512(SHA512(salt) || in)
	Sha512::hash(salt, saltlen, key);
	sha512.init();
	sha512.update(key, HASH_LENGTH);
	sha512.update(in,  inlen);
	sha512.finish(key);

	mem = new uint32_t[DATA_SIZE * memSize];
	for (uint64_t u = 0; u < upgradeLoops; u++)
	{
		// Init blowfish 448 bit
		blowfish.initKey448(key);

		// Fill data
		// data = SHA512(BIG_ENDIAN_64( 0) || key) ||
		//        SHA512(BIG_ENDIAN_64( 1) || key) ||
		//        ...
		//        SHA512(BIG_ENDIAN_64(31) || key)
		for (size_t i = 0; i < sizeof(data) / HASH_LENGTH; i++)
		{
			uint64_t tmp64 = WRITE_BIG_ENDIAN_64(i);
			sha512.init();
			sha512.update(&tmp64, sizeof(uint64_t));
			sha512.update(key,    HASH_LENGTH);
			sha512.finish(data + HASH_LENGTH / sizeof(uint32_t) * i);
		}

		// Init memory
		for (size_t i = 0; i < memSize; i++)
		{
			// data = blowfish_encrypt_cbc(data)
			// mem = mem || data
			blowfish.cbcEncrypt(data, data, DATA_BF_BLOCKS);
			memcpy(mem + DATA_SIZE * i, data, sizeof(data));
		}
		// data = blowfish_encrypt_cbc(data)
		blowfish.cbcEncrypt(data, data, DATA_BF_BLOCKS);

		// Work
		for (uint64_t i = 0; i < loops; i++)
		{
			for (size_t j = 0; j < memSize; j++)
			{
				// mem[j] = blowfish_encrypt_cbc(data ^ mem[j] ^ mem[last64Bits(data) & memMask])
				p = mem + DATA_SIZE * j;
				q = mem + DATA_SIZE * (READ_BIG_ENDIAN_64(((uint64_t*) data)[DATA_SIZE / 2 - 1]) & memMask);
				for (int k = 0; k < DATA_SIZE; k++)
				{
					p[k] ^= data[k] ^ q[k];
				}
				p = mem + DATA_SIZE * j;
				blowfish.cbcEncrypt(p, p, DATA_BF_BLOCKS);
				// data ^= mem[j]
				for (int k = 0; k < DATA_SIZE; k++)
				{
					data[k] ^= p[k];
				}
			}
		}

		// Finish
		// key = truncate(SHA512(SHA512(data || key)), outlen) || zeros(HASH_LENGTH - outlen)
		sha512.init();
		sha512.update(data, sizeof(data));
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
	memset(data, 0, sizeof(data));
	memset(key,  0, sizeof(key));
	memset(mem,  0, sizeof(uint32_t) * DATA_SIZE * memSize);
	delete [] mem;
	p = NULL;
	q = NULL;
	return 0;
}

int battcryptKdf(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	Sha512    sha512;
	uint32_t  data[DATA_SIZE];
	Blowfish  blowfish;
	uint64_t  key[HASH_LENGTH / sizeof(uint64_t)];
	// loops = 2, 3, 4, 6, 8, 12, 16, ...
	uint64_t  loops   = (uint64_t) ((t_cost & 1) + 2) << (t_cost >> 1);
	size_t    memSize = ((size_t) 4) << m_cost;
	size_t    memMask = memSize - 1;
	uint32_t *mem;
	uint32_t *p;
	uint32_t *q;

	assert(HASH_LENGTH % sizeof(uint64_t) == 0);
	assert((sizeof(uint32_t) * DATA_SIZE) % HASH_LENGTH == 0);
	assert(DATA_SIZE % 2 == 0);
#ifdef ARC_32
	assert(sizeof(memSize) >= sizeof(uint32_t));
	if (m_cost > 18 || (t_cost & 0xffff) > 62 || (t_cost >> 16) > 63 || outlen > HASH_LENGTH)
	{
		return 1;
	}
#else
	assert(sizeof(memSize) >= sizeof(uint64_t));
	if (m_cost > 50 || (t_cost & 0xffff) > 62 || (t_cost >> 16) > 63 || outlen > HASH_LENGTH)
	{
		return 1;
	}
#endif

	// key = SHA512(SHA512(salt) || in)
	Sha512::hash(salt, saltlen, key);
	sha512.init();
	sha512.update(key, HASH_LENGTH);
	sha512.update(in,  inlen);
	sha512.finish(key);

	mem = new uint32_t[DATA_SIZE * memSize];

	// Init blowfish 448 bit
	blowfish.initKey448(key);

	// Fill data
	// data = SHA512(BIG_ENDIAN_64( 0) || key) ||
	//        SHA512(BIG_ENDIAN_64( 1) || key) ||
	//        ...
	//        SHA512(BIG_ENDIAN_64(31) || key)
	for (size_t i = 0; i < sizeof(data) / HASH_LENGTH; i++)
	{
		uint64_t tmp = WRITE_BIG_ENDIAN_64(i);
		sha512.init();
		sha512.update(&tmp, sizeof(uint64_t));
		sha512.update(key,  HASH_LENGTH);
		sha512.finish(data + HASH_LENGTH / sizeof(uint32_t) * i);
	}

	// Init memory
	for (size_t i = 0; i < memSize; i++)
	{
		// data = blowfish_encrypt_cbc(data)
		// mem = mem || data
		blowfish.cbcEncrypt(data, data, DATA_BF_BLOCKS);
		memcpy(mem + DATA_SIZE * i, data, sizeof(data));
	}
	// data = blowfish_encrypt_cbc(data)
	blowfish.cbcEncrypt(data, data, DATA_BF_BLOCKS);

	// Work
	for (uint64_t i = 0; i < loops; i++)
	{
		for (size_t j = 0; j < memSize; j++)
		{
			// mem[j] = blowfish_encrypt_cbc(data ^ mem[j] ^ mem[last64Bits(data) & memMask])
			p = mem + DATA_SIZE * j;
			q = mem + DATA_SIZE * (READ_BIG_ENDIAN_64(((uint64_t*) data)[DATA_SIZE / 2 - 1]) & memMask);
			for (int k = 0; k < DATA_SIZE; k++)
			{
				p[k] ^= data[k] ^ q[k];
			}
			p = mem + DATA_SIZE * j;
			blowfish.cbcEncrypt(p, p, DATA_BF_BLOCKS);
			// data ^= mem[j]
			for (int k = 0; k < DATA_SIZE; k++)
			{
				data[k] ^= p[k];
			}
		}
	}

	// Finish
	// work = SHA512(data || key)
	// while length(out) < outlen
	//     out = out || SHA512(READ_BIG_ENDIAN_64(i) || work || in)
	//     i = i + 1
	uint64_t work[HASH_LENGTH / sizeof(uint64_t)];
	sha512.init();
	sha512.update(data, sizeof(data));
	sha512.update(key,  HASH_LENGTH);
	sha512.finish(work);
	for (int i = 0, left = (int) outlen; left > 0; i++, left -= HASH_LENGTH)
	{
		uint64_t tmp = WRITE_BIG_ENDIAN_64(i);
		sha512.init();
		sha512.update(&tmp, sizeof(tmp));
		sha512.update(work, HASH_LENGTH);
		sha512.update(in,   inlen);
		sha512.finish(out,  left);
		out = ((uint8_t*) out) + HASH_LENGTH;
	}

	// Clean up
	// TODO: find a secure wipe function
	memset(data, 0, sizeof(data));
	memset(work, 0, sizeof(work));
	memset(key,  0, sizeof(key));
	memset(mem,  0, sizeof(uint32_t) * DATA_SIZE * memSize);
	delete [] mem;
	p = NULL;
	q = NULL;
	return 0;
}
