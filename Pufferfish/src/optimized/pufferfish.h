/*  Authored by Jeremi Gosney, 2014
    Placed in the public domain.
 */

#pragma once

#define F(x)								\
(									\
    ((S[0][(x >> (64 - log2_sbox_words))		   ]  ^		\
      S[1][(x >> (48 - log2_sbox_words)) & (sbox_words - 1)]) +		\
      S[2][(x >> (32 - log2_sbox_words)) & (sbox_words - 1)]) ^		\
      S[3][(x >> (16 - log2_sbox_words)) & (sbox_words - 1)]		\
)

#define ENCIPHER							\
    L ^= P[0];								\
    R = (R ^ F(L)) ^ P[ 1];						\
    L = (L ^ F(R)) ^ P[ 2];						\
    R = (R ^ F(L)) ^ P[ 3];						\
    L = (L ^ F(R)) ^ P[ 4];						\
    R = (R ^ F(L)) ^ P[ 5];						\
    L = (L ^ F(R)) ^ P[ 6];						\
    R = (R ^ F(L)) ^ P[ 7];						\
    L = (L ^ F(R)) ^ P[ 8];						\
    R = (R ^ F(L)) ^ P[ 9];						\
    L = (L ^ F(R)) ^ P[10];						\
    R = (R ^ F(L)) ^ P[11];						\
    L = (L ^ F(R)) ^ P[12];						\
    R = (R ^ F(L)) ^ P[13];						\
    L = (L ^ F(R)) ^ P[14];						\
    R = (R ^ F(L)) ^ P[15];						\
    L = (L ^ F(R)) ^ P[16];						\
    R ^= P[17];								\
    LL = R;								\
    RR = L;								\
    L  = LL;								\
    R  = RR;


#define KEYCIPHER(a,b,c,d)						\
{									\
    L ^= (a);								\
    R ^= (b);								\
    ENCIPHER;								\
    (c) = L;								\
    (d) = R;								\
}


#define KEYCIPHER_NULL(a,b)						\
{									\
    ENCIPHER;								\
    (a) = L;								\
    (b) = R;								\
}


#define EXPANDKEY(x)							\
{									\
    P[ 0] ^= x[0];							\
    P[ 1] ^= x[1];							\
    P[ 2] ^= x[2];							\
    P[ 3] ^= x[3];							\
    P[ 4] ^= x[4];							\
    P[ 5] ^= x[5];							\
    P[ 6] ^= x[6];							\
    P[ 7] ^= x[7];							\
    P[ 8] ^= x[0];							\
    P[ 9] ^= x[1];							\
    P[10] ^= x[2];							\
    P[11] ^= x[3];							\
    P[12] ^= x[4];							\
    P[13] ^= x[5];							\
    P[14] ^= x[6];							\
    P[15] ^= x[7];							\
    P[16] ^= x[0];							\
    P[17] ^= x[1];							\
									\
    KEYCIPHER_NULL (P[ 0], P[ 1]);					\
    KEYCIPHER_NULL (P[ 2], P[ 3]);					\
    KEYCIPHER_NULL (P[ 4], P[ 5]);					\
    KEYCIPHER_NULL (P[ 6], P[ 7]);					\
    KEYCIPHER_NULL (P[ 8], P[ 9]);					\
    KEYCIPHER_NULL (P[10], P[11]);					\
    KEYCIPHER_NULL (P[12], P[13]);					\
    KEYCIPHER_NULL (P[14], P[15]);					\
    KEYCIPHER_NULL (P[16], P[17]);					\
									\
    for (i = 0; i < sbox_words; i+=2)					\
	KEYCIPHER_NULL (S[0][i], S[0][i+1]);				\
    for (i = 0; i < sbox_words; i+=2)					\
	KEYCIPHER_NULL (S[1][i], S[1][i+1]);				\
    for (i = 0; i < sbox_words; i+=2)					\
	KEYCIPHER_NULL (S[2][i], S[2][i+1]);				\
    for (i = 0; i < sbox_words; i+=2)					\
	KEYCIPHER_NULL (S[3][i], S[3][i+1]);				\
}


extern void *pufferfish (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw);

