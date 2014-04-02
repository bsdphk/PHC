/* PHC Candidate pufferfish - reference implementation
   Authored by Jeremi Gosney, 2014
   Placed in the public domain.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "../common/common.h"
#include "../common/itoa64.h"
#include "../common/api.h"
#include "pufferfish.h"

static void pf_initstate (puf_ctx *context, const void *pass, size_t passlen, const void *salt, size_t salt_len, unsigned int m_cost)
{
	/* this function is absolutely nothing like Blowfish_initstate(),
	   and is really what defines pufferfish. */

	int i, j;
	unsigned char *key_hash;
	unsigned char salt_hash[DIGEST_LEN];
	uint64_t *state;

	/* initialize the P-array with digits of Pi. this is the only part
	   of the function that resembles Blowfish_initstate() */
	puf_ctx initstate =
	{
		{
			0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0,
			0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
			0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917, 0x9216d5d98979fb1b,
			0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
			0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16,
			0x636920d871574e69, 0xa458fea3f4933d7e, 0x0d95748f728eb658
		}
	};

	/* calculate number of words per s-box */
	initstate.m_cost =  1 << m_cost;
	initstate.log2_sbox_words = m_cost + 5; /* 5 = log2(1024 / 4 / 8) */
	initstate.sbox_words = 1 << initstate.log2_sbox_words;

	/* the following steps initialize the dynamic s-boxes: */

	/* step 1: hash the salt with sha512 to generate the hmac key */
	SHA512 (salt, salt_len, salt_hash);

	/* step 2: hmac-sha512 the password using the hashed salt as
	   the key to initialize the state */
	state = (uint64_t*) HMAC_SHA512 (salt_hash, DIGEST_LEN, pass, passlen);

	/* step 3: fill the s-boxes by iterating over the state with sha512 */
	for (i = 0; i < NUM_SBOXES; i++)
	{
		initstate.S[i] = (uint64_t *) calloc (initstate.sbox_words, WORDSIZ);

		for (j = 0; j < initstate.sbox_words; j+=STATE_N)
		{
			SHA512 ((const unsigned char *) state, DIGEST_LEN, (unsigned char *)(initstate.S[i] + j));
			state = initstate.S[i] + j;
		}
	}

	/* hmac-sha512 the password again using the resulting
	   state as the key to generate the encryption key */
	key_hash = HMAC_SHA512 ((const unsigned char *) state, DIGEST_LEN, pass, passlen);

	/* set the context */
	*context = initstate;
	memmove (context->key, key_hash, DIGEST_LEN);
	memmove (context->salt, salt_hash, DIGEST_LEN);

	/* clean up openssl static data */
	memset (key_hash, 0, DIGEST_LEN);
}

/*
 this is the old f-function that i originally designed, but it turned out
 to be very, very, very, VERY slow. so i went back to using just shifts.

static uint64_t pf_f (puf_ctx *context, uint64_t x)
{
	uint64_t h = context->S[0][rotr64(x,61) % context->sbox_words]
		   + context->S[1][rotr64(x,22) % context->sbox_words];

	return ( h ^ context->S[2][rotr64(x,53) % context->sbox_words] )
		   + context->S[3][rotr64(x,33) % context->sbox_words];
}
*/

static uint64_t pf_f (puf_ctx *context, uint64_t x)
{
	/* this is the revised f-function that steve thomas and i came up with.
	   my original shifits-only design only used 48/64 bits, so steve came
	   up with the idea to shift n - log2_sbox_words to solve this problem */

	return ((context->S[0][(x >> (64 - context->log2_sbox_words))			         ]  ^
		 context->S[1][(x >> (48 - context->log2_sbox_words)) & (context->sbox_words - 1)]) +
		 context->S[2][(x >> (32 - context->log2_sbox_words)) & (context->sbox_words - 1)]) ^
		 context->S[3][(x >> (16 - context->log2_sbox_words)) & (context->sbox_words - 1)];
}

static void pf_encipher (puf_ctx *context, uint64_t *LL, uint64_t *RR)
{
	/* this function is identical to Blowfish_encipher(), except
	   it has been modified to use 64-bit words. */

	int i = 0;
	uint64_t L = *LL, R = *RR;

	for (i = 0; i < PUF_N; i+=2)
	{
		L ^= context->P[i];
		R ^= pf_f (context, L);
		R ^= context->P[i+1];
		L ^= pf_f (context, R);
	}

	L ^= context->P[16];
	R ^= context->P[17];
	*LL = R;
	*RR = L;
}


static void pf_ecb_encrypt (puf_ctx *context, uint8_t *data, size_t len)
{
	/* this function is identical to blf_ecb_encrypt(), except it has
	   been modified to use 64-bit words and a 128-bit blocksize. */

	uint64_t i, L = 0, R = 0;

	for (i = 0; i < len; i+=BLOCKSIZ)
	{
		uint8_to_uint64 (L, data, 0);
		uint8_to_uint64 (R, data, 8);

		pf_encipher (context, &L, &R);

		uint64_to_uchar (L, data, 0);
		uint64_to_uchar (R, data, 8);

		data+=BLOCKSIZ;
	}
}


static void pf_expandkey (puf_ctx *context, const uint64_t data[KEYSIZ], const uint64_t key[KEYSIZ])
{
	/* this function is largely identical to Blowfish_expandstate(), except
	   it has been modified to use 64-bit words, dynamic s-box size, and a
	   fixed key and data size of 256 bits. */

	int i, j;
	uint64_t L = 0, R = 0;

	for (i = 0; i < PUF_N + 2; i++)
		context->P[i] ^= key[i%KEYSIZ];

	for (i = 0; i < PUF_N + 2; i+=2)
	{
		L ^= data[i%KEYSIZ];
		R ^= data[(i+1)%KEYSIZ];

		pf_encipher (context, &L, &R);

		context->P[i]   = L;
		context->P[i+1] = R;
	}

	for (i = 0; i < NUM_SBOXES; i++)
	{
		for (j = 0; j < context->sbox_words; j+=2)
		{
			/* since we use dynamic s-boxes and encipher is called $sbox_words times,
			   this ends up being more expensive than blowfish for m_cost > 3. */

			L ^= data[j%KEYSIZ];
			R ^= data[(j+1)%KEYSIZ];

			pf_encipher (context, &L, &R);

			context->S[i][j]   = L;
			context->S[i][j+1] = R;
		}
	}
}

void *pufferfish (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw)
{
	/* the main pufferfish function. probably shouldn't call this directly */

	puf_ctx context;
	static unsigned char *out;

	long t_cost = 0, m_cost = 0, count = 0;
	uint64_t null_data[8] = { 0 };

	int i, j, settingslen, saltlen, blockcnt, bytes = 0, pos = 0;

	char *sptr;
	char tcost_str[5] = { '0', 'x', 0 };
	char mcost_str[11] = { '0', 'x', 0 };

	unsigned char *rawbuf;
	unsigned char decoded[255] = { 0 };
	unsigned char rawsalt[255] = { 0 };
	unsigned char ctext[] = "Drab as a fool, aloof as a bard.";

	/* parse the settings string */

	/* make sure we have a pufferfish hash */
	if (strncmp (PUF_ID, settings, PUF_ID_LEN))
		return NULL;

	settingslen = strlen (settings);
	sptr = settings + PUF_ID_LEN;

	/* find where the settings string ends */
	while (*sptr++ != '$' && pos < settingslen) pos++;

	settingslen = pos + PUF_ID_LEN + 1;

	/* decode the settings string */
	bytes = decode64 (decoded, pos, settings + PUF_ID_LEN);
	saltlen = bytes - 4;

	/* unpack t_cost value */
	memmove (tcost_str + 2, decoded, 2);
	t_cost = strtol (tcost_str, NULL, 16);

	/* unpack the m_cost value */
	memmove (mcost_str + 2, decoded + 2, 2);
	m_cost = strtol (mcost_str, NULL, 16);

	/* unpack the raw salt value */
	memmove (rawsalt, decoded + 4, saltlen);

	/* the follwing steps are identical to the eksblowfish algorithm */

	/* initialize the context */
	pf_initstate (&context, pass, passlen, rawsalt, saltlen, m_cost);

	/* expand the key ... */
	pf_expandkey (&context, context.salt, context.key);

	/* ... again and again */
	count = 1 << t_cost;
	do
	{
		pf_expandkey (&context, null_data, context.salt);
		pf_expandkey (&context, null_data, context.key);
	}
	while (--count);

	/* to support a variable output length (e.g., when used as a kdf)
	   at minimal cost while still providing good security, we treat
	   the following loop like a simple prng: we repeatedly encrypt
	   the ciphertext as the inner state, and hash the output. */

	blockcnt = (outlen + DIGEST_LEN - 1) / DIGEST_LEN;
	rawbuf = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));

	for (i = 0; i < blockcnt; i++)
	{
		for (j = 0; j < 64; j++)
			pf_ecb_encrypt (&context, ctext, 32);

		SHA512 ((const unsigned char *) ctext, 32, rawbuf + (i * DIGEST_LEN));
	}

	/* if the user just wants the raw bytes (e.g. when used as a kdf)
	   then just fill the output buffer with the raw bytes. otherwise,
	   generate a full ascii string to place in a database. */

	if (raw == true)
	{
		out = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));
		memmove (out, rawbuf, outlen);
	}
	else
	{
		out = (unsigned char *) calloc (settingslen + 1 + (blockcnt * DIGEST_LEN * 2), sizeof (unsigned char));
		memmove (out, settings, settingslen);
		encode64 ((char *) &out[settingslen], rawbuf, outlen);
	}

	/* cleanup */

	for (i = 0; i < NUM_SBOXES; i++)
	{
		for (j = 0; j < context.sbox_words; j++)
			context.S[i][j] = 0;
		free (context.S[i]);
	}

	memset (&context, 0, sizeof (puf_ctx));
	memset (ctext, 0, 32);
	free (rawbuf);

	return out;
}

