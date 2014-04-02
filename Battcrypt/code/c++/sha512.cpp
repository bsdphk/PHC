// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#include <string.h>
#include "sha512.h"

const uint64_t SHA512_CONSTS[80] = {
	UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd), UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc), UINT64_C(0x3956c25bf348b538), 
	UINT64_C(0x59f111f1b605d019), UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118), UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe), 
	UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2), UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1), UINT64_C(0x9bdc06a725c71235), 
	UINT64_C(0xc19bf174cf692694), UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3), UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65), 
	UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483), UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5), UINT64_C(0x983e5152ee66dfab), 
	UINT64_C(0xa831c66d2db43210), UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4), UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725), 
	UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70), UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926), UINT64_C(0x4d2c6dfc5ac42aed), 
	UINT64_C(0x53380d139d95b3df), UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8), UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b), 
	UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001), UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30), UINT64_C(0xd192e819d6ef5218), 
	UINT64_C(0xd69906245565a910), UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8), UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53), 
	UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8), UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb), UINT64_C(0x5b9cca4f7763e373), 
	UINT64_C(0x682e6ff3d6b2b8a3), UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60), UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec), 
	UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9), UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b), UINT64_C(0xca273eceea26619c), 
	UINT64_C(0xd186b8c721c0c207), UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178), UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6), 
	UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b), UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493), UINT64_C(0x3c9ebe0a15c9bebc), 
	UINT64_C(0x431d67c49c100d4c), UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a), UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)};

void sha512Block(const uint64_t block[16], uint64_t state[8]);

void Sha512::hash(const void *message, size_t length, void *out, uint32_t outLength)
{
	uint64_t block[16];
	uint64_t state[8] = {
		UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
		UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f), UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};
	size_t   left = length;

	while (left >= 128)
	{
		sha512Block((const uint64_t*) message, state);
		message = ((const uint64_t*) message) + 16;
		left -= 128;
	}
	memcpy(block, message, left);
	((uint8_t*) block)[left] = 0x80;
	memset(((uint8_t*) block) + (left + 1), 0, 128 - (left + 1));
	if (left >= 128 - 16)
	{
		sha512Block(block, state);
		for (uint32_t i = 0; i < 14; i++)
		{
			block[i] = 0;
		}
	}
	uint64_t tmp;
	tmp = ((uint64_t) length) >> (64 - 3);
	block[14] = WRITE_BIG_ENDIAN_64(tmp);
	tmp = ((uint64_t) length) << 3;
	block[15] = WRITE_BIG_ENDIAN_64(tmp);
	sha512Block(block, state);
	if (outLength > 64)
	{
		outLength = 64;
	}
	for (uint32_t i = 0, end = outLength / 8; i < end; i++)
	{
		((uint64_t*) out)[i] = WRITE_BIG_ENDIAN_64(state[i]);
	}
	for (uint32_t i = outLength & ~7, shift = 56; i < outLength; i++, shift -= 8)
	{
		((uint8_t*) out)[i] = (uint8_t) (state[i / 8] >> shift);
	}
}

void Sha512::init()
{
	m_messageLengthHi = 0;
	m_messageLengthLo = 0;
	m_state[0] = UINT64_C(0x6a09e667f3bcc908);
	m_state[1] = UINT64_C(0xbb67ae8584caa73b);
	m_state[2] = UINT64_C(0x3c6ef372fe94f82b);
	m_state[3] = UINT64_C(0xa54ff53a5f1d36f1);
	m_state[4] = UINT64_C(0x510e527fade682d1);
	m_state[5] = UINT64_C(0x9b05688c2b3e6c1f);
	m_state[6] = UINT64_C(0x1f83d9abfb41bd6b);
	m_state[7] = UINT64_C(0x5be0cd19137e2179);
}

void Sha512::update(const void *message, size_t length)
{
	size_t pos  = (size_t) m_messageLengthLo & 127;
	size_t left = length;

	if (pos + left >= 128)
	{
		memcpy(((uint8_t*) m_block) + pos, message, 128 - pos);
		sha512Block(m_block, m_state);
		message = ((const uint8_t*) message) + 128 - pos;
		left -= 128 - pos;
		while (left >= 128)
		{
			sha512Block(((const uint64_t*) message), m_state);
			message = ((const uint8_t*) message) + 128;
			left -= 128;
		}
		memcpy(m_block, message, left);
	}
	else
	{
		memcpy(((uint8_t*) m_block) + pos, message, left);
	}
	m_messageLengthLo += length;
	if (m_messageLengthLo < length)
	{
		m_messageLengthHi++;
	}
}

void Sha512::finish(void *out, uint32_t outLength)
{
	uint64_t lengthHi = m_messageLengthHi;
	uint64_t lengthLo = m_messageLengthLo;

	((uint8_t*) m_block)[lengthLo % 128] = 0x80;
	memset(((uint8_t*) m_block) + (lengthLo % 128 + 1), 0, 128 - (lengthLo % 128 + 1));
	if (lengthLo % 128 >= 128 - 16)
	{
		sha512Block(m_block, m_state);
		for (uint32_t i = 0; i < 15; i++)
		{
			m_block[i] = 0;
		}
	}
	lengthHi  = (lengthHi << 3) + (lengthLo >> (64 - 3));
	lengthLo *= 8;
	m_block[14] = WRITE_BIG_ENDIAN_64(lengthHi);
	m_block[15] = WRITE_BIG_ENDIAN_64(lengthLo);
	sha512Block(m_block, m_state);
	if (outLength > 64)
	{
		outLength = 64;
	}
	for (uint32_t i = 0, end = outLength / 8; i < end; i++)
	{
		((uint64_t*) out)[i] = WRITE_BIG_ENDIAN_64(m_state[i]);
	}
	for (uint32_t i = outLength & ~7, shift = 56; i < outLength; i++, shift -= 8)
	{
		((uint8_t*) out)[i] = (uint8_t) (m_state[i / 8] >> shift);
	}
}

void sha512Block(const uint64_t block[16], uint64_t state[8])
{
#define ROTR(n,s) ((n >> s) | (n << (64 - s)))
#define SHA512_STEP(a,b,c,d,e,f,g,h,w,i) \
	h += (ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41)) + ((e & f) ^ (~e & g)) + SHA512_CONSTS[i] + w[i]; \
	d += h; \
	h += (ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));

	uint64_t w[80];
	uint64_t a = state[0];
	uint64_t b = state[1];
	uint64_t c = state[2];
	uint64_t d = state[3];
	uint64_t e = state[4];
	uint64_t f = state[5];
	uint64_t g = state[6];
	uint64_t h = state[7];

	for (int i = 0; i < 16; i++)
	{
		w[i] = READ_BIG_ENDIAN_64(block[i]);
	}
	for (int i = 16; i < 80; i++)
	{
        w[i] = 
			w[i-16] +
			w[i- 7] +
			(ROTR(w[i-15],  1) ^ ROTR(w[i-15],  8) ^ (w[i-15] >> 7)) +
			(ROTR(w[i- 2], 19) ^ ROTR(w[i- 2], 61) ^ (w[i- 2] >> 6));
	}

	for (int i = 0; i < 80; i += 8)
	{
		SHA512_STEP(a,b,c,d,e,f,g,h,w,i+0);
		SHA512_STEP(h,a,b,c,d,e,f,g,w,i+1);
		SHA512_STEP(g,h,a,b,c,d,e,f,w,i+2);
		SHA512_STEP(f,g,h,a,b,c,d,e,w,i+3);
		SHA512_STEP(e,f,g,h,a,b,c,d,w,i+4);
		SHA512_STEP(d,e,f,g,h,a,b,c,w,i+5);
		SHA512_STEP(c,d,e,f,g,h,a,b,w,i+6);
		SHA512_STEP(b,c,d,e,f,g,h,a,w,i+7);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

#undef ROTR
#undef SHA512_STEP
}
