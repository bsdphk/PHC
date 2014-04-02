/* PHC Candidate pufferfish - optimized implementation.
   Authored by Jeremi Gosney, 2014
   Placed in the public domain.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../common/common.h"
#include "../common/itoa64.h"
#include "../common/api.h"
#include "sha512.h"
#include "pufferfish.h"


void *pufferfish (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw)
{

	static unsigned char *out;

	long t_cost = 0, m_cost = 0, sbox_words, log2_sbox_words, count = 0;
	uint64_t state[8], tmpbuf[8], salt_hash[8], key_hash[8];
	uint64_t L = 0, R = 0, LL = 0, RR = 0;
	uint64_t *S[4], P[18];

	int i, j, settingslen, saltlen, blockcnt, bytes = 0, pos = 0;

	char *sptr;
	char tcost_str[5] = { '0', 'x', 0 };
	char mcost_str[11] = { '0', 'x', 0 };

	unsigned char *rawbuf;
	unsigned char decoded[255] = { 0 };
	unsigned char rawsalt[255] = { 0 };

	uint64_t ctext[4] = { 0x4472616220617320, 0x6120666f6f6c2c20, 0x616c6f6f66206173, 0x206120626172642e };


	if (strncmp (PUF_ID, settings, PUF_ID_LEN))
		return NULL;

	settingslen = strlen (settings);
	sptr = settings + PUF_ID_LEN;

	while (*sptr++ != '$' && pos < settingslen) pos++;

	settingslen = pos + PUF_ID_LEN + 1;

	bytes = decode64 (decoded, pos, settings + PUF_ID_LEN);
	saltlen = bytes - 4;

	memcpy (tcost_str + 2, decoded, 2);
	t_cost = strtol (tcost_str, NULL, 16);

	memcpy (mcost_str + 2, decoded + 2, 2);
	m_cost = strtol (mcost_str, NULL, 16);

	memcpy (rawsalt, decoded + 4, saltlen);

	log2_sbox_words = m_cost + 5;
	 sbox_words = 1 << log2_sbox_words;
	 m_cost = 1 << m_cost;

	pf_sha512 ((const unsigned char *) rawsalt, saltlen, salt_hash);

	 pf_hmac_sha512 ((const unsigned char *) salt_hash, DIGEST_LEN, (const unsigned char *) pass, passlen, state);

	 for (i = 0; i < 4; i++)
	 {
		  S[i] = (uint64_t *) alloca (sbox_words * sizeof (uint64_t));

		  for (j=0; j < sbox_words; j+=8)
		  {
			   pf_sha512 ((const unsigned char *) state, DIGEST_LEN, S[i]+j);

			   state[0] = S[i][j+0];
			   state[1] = S[i][j+1];
			   state[2] = S[i][j+2];
			   state[3] = S[i][j+3];
			   state[4] = S[i][j+4];
			   state[5] = S[i][j+5];
			   state[6] = S[i][j+6];
			   state[7] = S[i][j+7];
		  }
	 }

	 pf_hmac_sha512 ((const unsigned char *) state, DIGEST_LEN, (const unsigned char *) pass, passlen, key_hash);

	 P[ 0] = 0x243f6a8885a308d3 ^ key_hash[0];
	 P[ 1] = 0x13198a2e03707344 ^ key_hash[1];
	 P[ 2] = 0xa4093822299f31d0 ^ key_hash[2];
	 P[ 3] = 0x082efa98ec4e6c89 ^ key_hash[3];
	 P[ 4] = 0x452821e638d01377 ^ key_hash[4];
	 P[ 5] = 0xbe5466cf34e90c6c ^ key_hash[5];
	 P[ 6] = 0xc0ac29b7c97c50dd ^ key_hash[6];
	 P[ 7] = 0x3f84d5b5b5470917 ^ key_hash[7];
	 P[ 8] = 0x9216d5d98979fb1b ^ key_hash[0];
	 P[ 9] = 0xd1310ba698dfb5ac ^ key_hash[1];
	 P[10] = 0x2ffd72dbd01adfb7 ^ key_hash[2];
	 P[11] = 0xb8e1afed6a267e96 ^ key_hash[3];
	 P[12] = 0xba7c9045f12c7f99 ^ key_hash[4];
	 P[13] = 0x24a19947b3916cf7 ^ key_hash[5];
	 P[14] = 0x0801f2e2858efc16 ^ key_hash[6];
	 P[15] = 0x636920d871574e69 ^ key_hash[7];
	 P[16] = 0xa458fea3f4933d7e ^ key_hash[0];
	 P[17] = 0x0d95748f728eb658 ^ key_hash[1];

	 KEYCIPHER (salt_hash[0], salt_hash[1], P[ 0], P[ 1]);
	 KEYCIPHER (salt_hash[2], salt_hash[3], P[ 2], P[ 3]);
	 KEYCIPHER (salt_hash[4], salt_hash[5], P[ 4], P[ 5]);
	 KEYCIPHER (salt_hash[6], salt_hash[7], P[ 6], P[ 7]);
	 KEYCIPHER (salt_hash[0], salt_hash[1], P[ 8], P[ 9]);
	 KEYCIPHER (salt_hash[2], salt_hash[3], P[10], P[11]);
	 KEYCIPHER (salt_hash[4], salt_hash[5], P[12], P[13]);
	 KEYCIPHER (salt_hash[6], salt_hash[7], P[14], P[15]);
	 KEYCIPHER (salt_hash[0], salt_hash[1], P[16], P[17]);

	 for (i = 0; i < sbox_words; i+=2)
		  KEYCIPHER (salt_hash[i&7], salt_hash[(i+1)&7], S[0][i], S[0][i+1]);
	 for (i = 0; i < sbox_words; i+=2)
		  KEYCIPHER (salt_hash[i&7], salt_hash[(i+1)&7], S[1][i], S[1][i+1]);
	 for (i = 0; i < sbox_words; i+=2)
		  KEYCIPHER (salt_hash[i&7], salt_hash[(i+1)&7], S[2][i], S[2][i+1]);
	 for (i = 0; i < sbox_words; i+=2)
		  KEYCIPHER (salt_hash[i&7], salt_hash[(i+1)&7], S[3][i], S[3][i+1]);

	 count = 1 << t_cost;
	 do
	 {
		  L = R = 0; EXPANDKEY (salt_hash);
		  L = R = 0; EXPANDKEY (key_hash);
	 }
	 while (--count);

	blockcnt = (outlen + DIGEST_LEN - 1) / DIGEST_LEN;
	rawbuf = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));

	for (i = 0; i < blockcnt; i++)
	{
		 count = 64;
	 	do
		 {
			L = ctext[0];
	 		R = ctext[1];
		  	ENCIPHER;
			ctext[0] = L;
	 		ctext[1] = R;
			L = ctext[2];
	 		R = ctext[3];
		  	ENCIPHER;
			ctext[2] = L;
	 		ctext[3] = R;
		 }
	 	while (--count);

		ctext[0] = __builtin_bswap64 (ctext[0]);
	 	ctext[1] = __builtin_bswap64 (ctext[1]);
		ctext[2] = __builtin_bswap64 (ctext[2]);
	 	ctext[3] = __builtin_bswap64 (ctext[3]);

		pf_sha512 ((const unsigned char *) ctext, 32, tmpbuf);
		memcpy (rawbuf + (i * DIGEST_LEN), (unsigned char *) tmpbuf, 64);
	}

	if (raw == true)
	{
		out = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));
		memcpy (out, rawbuf, outlen);
	}
	else
	{
		out = (unsigned char *) calloc (settingslen + 1 + (blockcnt * DIGEST_LEN * 2), sizeof (unsigned char));
		memcpy (out, settings, settingslen);
		encode64 ((char *) &out[settingslen], rawbuf, outlen);
	}

	memset (ctext, 0, 32);
	free (rawbuf);

	return out;
}
