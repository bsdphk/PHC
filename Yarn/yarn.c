#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "yarn.h"

static const uint64_t blake2_iv[8] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const int blake2_sigma[10][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};

static uint32_t pack8to32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (uint32_t) a | ((uint32_t) b << 8) | ((uint32_t) c << 16) | ((uint32_t) d << 24);
}

static uint64_t pack32to64(uint32_t a, uint32_t b) {
	return (uint64_t) a | ((uint64_t) b << 32);
}

static void unpack64to8n(uint8_t *res, uint64_t a, int count) {
	int i;
	for (i = 0; i < count; i++) {
		res[i] = (uint8_t) (a >> (8 * i));
	}
}

static void strto64(uint64_t *out, const void *in, size_t inlen) {
	uint64_t buffer = 0;
	size_t i;
	for (i = 0; i < inlen; i++) {
		buffer |= (uint64_t) (((const uint8_t *) in)[i]) << (8 * (i % 8));
		if (i % 8 == 7) {
			out[i / 8] = buffer;
			buffer = 0;
		}
	}
	if (inlen % 8 != 0) {
		out[inlen / 8] = buffer;
	}
}

static void init_blake2b(uint64_t chain_value[8], size_t outlen, const void *salt, size_t saltlen, const void *pers, size_t perslen) {
	uint64_t salt64[2], pers64[2];
	assert(1 <= outlen && outlen <= 64 && saltlen <= 16 && perslen <= 16);
	memcpy(chain_value, blake2_iv, 64);
	chain_value[0] ^= pack32to64(pack8to32(outlen, 0, 1, 1), 0);
	memset(salt64, 0, 16);
	strto64(salt64, salt, saltlen);
	memset(pers64, 0, 16);
	strto64(pers64, pers, perslen);
	chain_value[4] ^= salt64[0];
	chain_value[5] ^= salt64[1];
	chain_value[6] ^= pers64[0];
	chain_value[7] ^= pers64[1];
}

static uint64_t rot64(uint64_t a, int n) {
	return (a >> n) | (a << (64 - n));
}

static void blake2b_g(int r, int i, uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d, const uint64_t block[16]) {
	*a = *a + *b + block[blake2_sigma[r % 10][2 * i]];
	*d = rot64(*d ^ *a, 32);
	*c = *c + *d;
	*b = rot64(*b ^ *c, 24);
	*a = *a + *b + block[blake2_sigma[r % 10][2 * i + 1]];
	*d = rot64(*d ^ *a, 16);
	*c = *c + *d;
	*b = rot64(*b ^ *c, 63);
}

static void blake2b_compress(uint64_t chain_value[8], const void *block, uint64_t t0, uint64_t t1, uint64_t f0, uint64_t f1) {
	uint64_t state[16], block64[16];
	int i;
	memcpy(state, chain_value, 64);
	memcpy(state + 8, blake2_iv, 64);
	state[12] ^= t0;
	state[13] ^= t1;
	state[14] ^= f0;
	state[15] ^= f1;
	strto64(block64, block, 128);
	for (i = 0; i < 12; i++) {
		blake2b_g(i, 0, &state[0], &state[4], &state[8], &state[12], block64);
		blake2b_g(i, 1, &state[1], &state[5], &state[9], &state[13], block64);
		blake2b_g(i, 2, &state[2], &state[6], &state[10], &state[14], block64);
		blake2b_g(i, 3, &state[3], &state[7], &state[11], &state[15], block64);
		blake2b_g(i, 4, &state[0], &state[5], &state[10], &state[15], block64);
		blake2b_g(i, 5, &state[1], &state[6], &state[11], &state[12], block64);
		blake2b_g(i, 6, &state[2], &state[7], &state[8], &state[13], block64);
		blake2b_g(i, 7, &state[3], &state[4], &state[9], &state[14], block64);
	}
	for (i = 0; i < 8; i++) {
		chain_value[i] ^= state[i] ^ state[i + 8];
	}
}

static void blake2b_process(uint64_t state[8], const void *in, size_t inlen) {
	size_t i;
	char buffer[128];
	for (i = 0; i + 128 < inlen; i += 128) {
		blake2b_compress(state, (const char *) in + i, (uint64_t) (i + 128), 0, 0, 0);
	}
	memcpy(buffer, (const char *) in + i, inlen - i);
	memset(buffer + (inlen - i), 0, 128 - (inlen - i));
	blake2b_compress(state, buffer, inlen, 0, 0xffffffffffffffff, 0);
}

static void blake2b_hash(uint64_t state[8], size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, const void *pers, size_t perslen) {
	init_blake2b(state, outlen, salt, saltlen, pers, perslen);
	blake2b_process(state, in, inlen);
}

static void unpack_state(void *out, size_t outlen, const uint64_t state[8]) {
	size_t i;
	for (i = 0; i < 8 && 8 * i < outlen; i++) {
		unpack64to8n((uint8_t *) out + 8 * i, state[i], outlen < 8 * (i + 1) ? outlen - 8 * i : 8);
	}
}

void blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, const void *pers, size_t perslen) {
	uint64_t state[8];
	blake2b_hash(state, outlen, in, inlen, salt, saltlen, pers, perslen);
	unpack_state(out, outlen, state);
}

void blake2b_expand(uint64_t state[8], void *exp, size_t explen, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, const void *pers, size_t perslen) {
	uint64_t tempstate[8];
	char buffer[128];
	size_t i;
	blake2b_hash(state, outlen, in, inlen, salt, saltlen, pers, perslen);
	memset(buffer, 0, 128);
	for (i = 0; i < explen; i += 64) {
		memcpy(tempstate, state, 64);
		blake2b_compress(tempstate, buffer, i / 64, 0, 0, 0xffffffffffffffff);
		unpack_state(exp + i, explen < i + 64 ? explen - i : 64, tempstate);
	}
}

static const uint8_t aes_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aes_dbl[256] = {
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
	0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
	0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
	0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
	0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
	0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
	0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
	0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};

static void aesenc(uint8_t buffer[16], const uint8_t key[16]) {
	int i;
	uint8_t tmp[16];
	for (i = 0; i < 16; i++) {
		buffer[i] = aes_sbox[buffer[i]];
	}
	for (i = 0; i < 16; i++) {
		tmp[i] = buffer[(i + 4 * (i % 4)) % 16];
	}
	for (i = 0; i < 16; i++) {
		int r = i % 4;
		int c = i / 4;
		buffer[i] = aes_dbl[tmp[i]] ^
			tmp[4 * c + ((r + 1) % 4)] ^ aes_dbl[tmp[4 * c + ((r + 1) % 4)]] ^
			tmp[4 * c + ((r + 2) % 4)] ^ tmp[4 * c + ((r + 3) % 4)];
	}
	for (i = 0; i < 16; i++) {
		buffer[i] ^= key[i];
	}
}

static void rotate_state(uint8_t (*state)[16], size_t par) {
	uint8_t tmp[16];
	memcpy(tmp, state[0], 16);
	memmove(state[0], state[1], 16 * (par - 1));
	memcpy(state[par - 1], tmp, 16);
}

static size_t integerify(const uint8_t block[16], unsigned int m_cost) {
	size_t res = 0;
	unsigned int i;
	for (i = 0; i < sizeof(size_t) && i < 16; i++) {
		res |= (size_t) block[i] << (8 * i);
	}
	return (res >> 4) & ((1ULL << m_cost) - 1);
}

int yarn(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, unsigned int par, unsigned int initrnd, unsigned int m_step, const void *pers, size_t perslen) {
	uint64_t blake2b_state[8];
	size_t i, j;
	uint8_t (*state)[16] = NULL, (*memory)[16] = NULL, (*keys)[16], *addr;
	if (!(1 <= outlen && outlen <= 64 && saltlen <= 16 && m_cost < sizeof(size_t) * 8 - 4 && par > 0 && perslen <= 16)) {
		/* Invalid parameters */
		return 0;
	}
	if (!(state = malloc(16 * (par + 1 + initrnd))) || !(memory = malloc(16ULL << m_cost))) {
		if (state != NULL) {
			free(state);
		}
		return 0;
	}
	keys = state + par;
	addr = state[par + initrnd];
	blake2b_expand(blake2b_state, state, 16 * (par + initrnd + 1), outlen, in, inlen, salt, saltlen, pers, perslen);
	for (i = 0; i < 1ULL << m_cost; i++) {
		memcpy(memory[i], state[0], 16);
		for (j = 0; j < initrnd; j++) {
			aesenc(state[0], keys[j]);
		}
		rotate_state(state, par);
	}
	for (i = 0; i < t_cost; i++) {
		if (i % m_step == m_step - 1) {
			size_t idx = integerify(addr, m_cost);
			for (j = 0; j < 16; j++) {
				addr[j] = memory[idx][j] ^ state[1 % par][j];
			}
			memcpy(memory[idx], state[1 % par], 16);
			aesenc(state[0], addr);
		} else {
			uint8_t tmp[16];
			memcpy(tmp, state[1 % par], 16);
			aesenc(state[0], tmp);
		}
		rotate_state(state, par);
	}
	blake2b_process(blake2b_state, state, 16 * par);
	unpack_state(out, outlen, blake2b_state);
	free(state);
	free(memory);
	return 1;
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
	return !yarn(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, 6, 10, 72, NULL, 0);
}
