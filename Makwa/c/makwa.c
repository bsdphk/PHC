/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/*
 * We use SHA-256, SHA-512, HMAC and the big integer code from OpenSSL.
 */
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "makwa.h"

/*
 * Each encoded format (modulus, private key, set of delegation
 * parameters, delegation request and delegation response) begins with a
 * four-byte header, which is the big-endian encoding of one of the
 * following values.
 */
#define MAGIC_PUBKEY       0x55414D30
#define MAGIC_PRIVKEY      0x55414D31
#define MAGIC_DELEG_PARAM  0x55414D32
#define MAGIC_DELEG_REQ    0x55414D33
#define MAGIC_DELEG_ANS    0x55414D34

/* see makwa.h */
int
makwa_kdf(int hash_function,
	const void *src, size_t src_len,
	void *dst, size_t dst_len)
{
	HMAC_CTX hc;
	const EVP_MD *mdf;
	size_t r;
	unsigned char K[64], V[64], b;
	unsigned mlen;

	HMAC_CTX_init(&hc);
	switch (hash_function) {
	case MAKWA_SHA256:
		mdf = EVP_sha256();
		r = 32;
		break;
	case MAKWA_SHA512:
		mdf = EVP_sha512();
		r = 64;
		break;
	default:
		return MAKWA_BADPARAM;
	}

	/*
	 * HMAC_Init_ex(), HMAC_Update() and HMAC_Final() return 'void'
	 * before OpenSSL-1.0.0, and 'int' since that version. MacOS X
	 * still uses a pre-1.0.0 version. Since we use the default
	 * implementation which should be software-based, no failure is
	 * actually expected.
	 */

	/* 1. V <- 0x01 0x01 0x01 ... 0x01 */
	memset(V, 0x01, r);

	/* 2. K <- 0x00 0x00 0x00 ... 0x00 */
	memset(K, 0x00, r);

	/* 3. K <- HMAC_K(V || 0x00 || m) */
	HMAC_Init_ex(&hc, K, r, mdf, NULL);
	HMAC_Update(&hc, V, r);
	b = 0x00;
	HMAC_Update(&hc, &b, 1);
	HMAC_Update(&hc, src, src_len);
	HMAC_Final(&hc, K, &mlen);
	if (mlen != r) {
		return MAKWA_HMAC_ERROR;
	}

	/* 4. V <- HMAC_K(V) */
	HMAC_Init_ex(&hc, K, r, NULL, NULL);
	HMAC_Update(&hc, V, r);
	HMAC_Final(&hc, V, &mlen);
	if (mlen != r) {
		return MAKWA_HMAC_ERROR;
	}

	/* 5. K <- HMAC_K(V || 0x01 || m) */
	HMAC_Init_ex(&hc, K, r, NULL, NULL);
	HMAC_Update(&hc, V, r);
	b = 0x01;
	HMAC_Update(&hc, &b, 1);
	HMAC_Update(&hc, src, src_len);
	HMAC_Final(&hc, K, &mlen);
	if (mlen != r) {
		return MAKWA_HMAC_ERROR;
	}

	/* 6. V <- HMAC_K(V) */
	HMAC_Init_ex(&hc, K, r, NULL, NULL);
	HMAC_Update(&hc, V, r);
	HMAC_Final(&hc, V, &mlen);
	if (mlen != r) {
		return MAKWA_HMAC_ERROR;
	}

	/* 7. and 8. */
	while (dst_len > 0) {
		size_t clen;

		HMAC_Init_ex(&hc, K, r, NULL, NULL);
		HMAC_Update(&hc, V, r);
		HMAC_Final(&hc, V, &mlen);
		if (mlen != r) {
			return MAKWA_HMAC_ERROR;
		}
		clen = dst_len;
		if (clen > r) {
			clen = r;
		}
		memcpy(dst, V, clen);
		dst = (unsigned char *)dst + clen;
		dst_len -= clen;
	}
	HMAC_CTX_cleanup(&hc);
	return MAKWA_OK;
}

/* see makwa.h */
int
makwa_make_new_salt(void *salt, size_t salt_len)
{
	/*
	 * A cryptographically strong PRNG is kinda overkill for a salt,
	 * but it does not hurt to use one.
	 */
	if (RAND_bytes(salt, salt_len) < 0) {
		return MAKWA_RAND_ERROR;
	}
	return MAKWA_OK;
}

/*
 * Some helper macros.
 *
 * In most of the remaining functions, exit is done through a code
 * sequence at the end, where temporary variables are deallocated.
 * The code sequence is reached through a 'goto' (label is 'exit_err')
 * and the function return value is held in the variable 'err'.
 *
 * CZ(expr) evaluates 'expr'; if it returns a zero value (or NULL
 * pointer), then the function will exit with a MAKWA_NOMEM error code.
 *
 * CZX(expr, errcode) evaluates 'expr'; if it returns a non-zero value,
 * then the function will exit with 'errcode' as error code.
 *
 * RETURN(errcode) exits the function with 'errcode' as error code.
 *
 * CF(expr) evaluates 'expr' and stores the result (of type 'int') into
 * the 'err' variable. If it is negative, then the function exits and
 * returns that value.
 *
 * FREE(x) calls free() on x (a pointer) if x is not NULL.
 *
 * FREE_BN(x) calls BN_clear_free() on x (a BIGNUM*) if x is not NULL.
 *
 * FREE_BNCTX(c) calls BN_CTX_free() on c (a BN_CTX*) if c is not NULL.
 *
 * FREE_MCTX(m) calls BN_MONT_CTX_free() on m (a BN_MONT_CTX*) if m is
 * not NULL.
 *
 * DO_BUFFER(out, out_len, len) applies the "output buffer semantics"
 * (see makwa.h) on out/out_len, for a predicted output length of 'len'
 * bytes.
 *
 * FUNCTION_EXIT is a non-statement macro which sets 'err' to MAKWA_OK
 * (for a successful exit) and defines the 'exit_err' label. It introduces
 * the function exit sequence, which must terminate with: 'return err;'
 */

#define CZ(x)   CZX(x, MAKWA_NOMEM)

#define CZX(x, errcode)   do { \
		if ((x) == 0) { \
			RETURN(errcode); \
		} \
	} while (0)

#define RETURN(errcode)   do { \
		err = (errcode); \
		goto exit_err; \
	} while (0)

#define CF(x)   do { \
		err = (x); \
		if (err < 0) { \
			goto exit_err; \
		} \
	} while (0)

#define FREE(x)   do { \
		void *tmp_free = (x); \
		if (tmp_free != NULL) { \
			free(tmp_free); \
		} \
	} while (0)

#define FREE_BN(x)   do { \
		BIGNUM *tmp_free = (x); \
		if (tmp_free != NULL) { \
			BN_clear_free(tmp_free); \
		} \
	} while (0)

#define FREE_BNCTX(x)   do { \
		BN_CTX *tmp_free = (x); \
		if (tmp_free != NULL) { \
			BN_CTX_free(tmp_free); \
		} \
	} while (0)

#define FREE_MCTX(x)   do { \
		BN_MONT_CTX *tmp_free = (x); \
		if (tmp_free != NULL) { \
			BN_MONT_CTX_free(tmp_free); \
		} \
	} while (0)

#define DO_BUFFER(out, out_len, len)   do { \
		void *macro_out = (out); \
		size_t *macro_out_len = (out_len); \
		size_t macro_len = (len); \
		if (macro_out == NULL) { \
			if (macro_out_len != NULL) { \
				*macro_out_len = macro_len; \
			} \
			RETURN(MAKWA_OK); \
		} else if (macro_out_len != NULL) { \
			size_t macro_pred_len = *macro_out_len; \
			*macro_out_len = macro_len; \
			if (macro_pred_len < macro_len) { \
				RETURN(MAKWA_BUFFER_TOO_SMALL); \
			} \
		} \
	} while (0)

#define FUNCTION_EXIT   err = MAKWA_OK; exit_err

/*
 * Decode a 16-bit integer (big-endian).
 */
static unsigned
decode_16(const void *src, size_t off)
{
	const unsigned char *buf;

	buf = src;
	return ((unsigned)buf[off + 0] << 8)
		| (unsigned)buf[off + 1];
}

/*
 * Decode a 32-bit integer (big-endian).
 */
static unsigned long
decode_32(const void *src, size_t off)
{
	const unsigned char *buf;

	buf = src;
	return ((unsigned long)buf[off + 0] << 24)
		| ((unsigned long)buf[off + 1] << 16)
		| ((unsigned long)buf[off + 2] << 8)
		| (unsigned long)buf[off + 3];
}

/*
 * Decode a big integer value, using the format described in the Makwa
 * specification, section A.5 (this is also the MPI format from OpenPGP;
 * warning: OpenSSL also has a format which it calls "MPI" but is
 * distinct from the one we use).
 *
 * The MPI is located at offset '*off' in the 'src' buffer (offest is
 * in bytes). The total length of 'src' is provided in 'len'. When the
 * integer has been decoded, '*off' is adjusted to point to the first
 * byte immediately following the MPI in the buffer. The big integer is
 * decoded into 'v'.
 */
static int
decode_mpi(const void *src, size_t *off, size_t len, BIGNUM *v)
{
	const unsigned char *buf;
	size_t mlen;

	buf = src;
	if (*off + 2 > len) {
		return MAKWA_BADPARAM;
	}
	mlen = decode_16(buf, *off);
	if (mlen > (len - *off - 2)) {
		return MAKWA_BADPARAM;
	}
	if (BN_bin2bn(buf + *off + 2, mlen, v) == NULL) {
		return MAKWA_NOMEM;
	}
	*off += 2 + mlen;
	return MAKWA_OK;
}

/*
 * Encode a 16-bit integer (big-endian).
 */
static void
encode_16(void *out, unsigned x)
{
	unsigned char *buf;

	buf = out;
	buf[0] = (x >> 8) & 0xFF;
	buf[1] = x & 0xFF;
}

/*
 * Encode a 32-bit integer (big-endian).
 */
static void
encode_32(void *out, unsigned long x)
{
	unsigned char *buf;

	buf = out;
	buf[0] = (x >> 24) & 0xFF;
	buf[1] = (x >> 16) & 0xFF;
	buf[2] = (x >> 8) & 0xFF;
	buf[3] = x & 0xFF;
}

/*
 * Encode a big integer in MPI format. The out/out_len values use the
 * "output buffer semantics".
 */
static int
encode_mpi(BIGNUM *v, void *out, size_t *out_len)
{
	unsigned char *buf;
	size_t len;
	int err;

	if (BN_is_negative(v)) {
		RETURN(MAKWA_BADPARAM);
	}
	len = BN_num_bytes(v);
	if (len > 65535) {
		RETURN(MAKWA_TOOLARGE);
	}
	DO_BUFFER(out, out_len, len + 2);
	buf = out;
	encode_16(buf, len);
	BN_bn2bin(v, buf + 2);

FUNCTION_EXIT:
	return err;
}

static size_t
mpi_length(BIGNUM *v)
{
	return BN_num_bytes(v) + 2;
}

/*
 * This function generates a random prime integer of the specified size
 * (in bits, between 2 ans 16384 bits). The top two bits of the prime
 * are equal to 1 (this is meant so that the product of two such primes
 * reliably reaches a given target size); moreover, the prime is equal to
 * 3 modulo 4 (this last property is what makes this function differ
 * from OpenSSL's BN_generate_prime()).
 */
static int
rand_prime(int size, BIGNUM *p)
{
	int err;
	BN_CTX *bnctx;

	bnctx = NULL;
	if (size < 2 || size > 16384) {
		RETURN(MAKWA_TOOLARGE);
	}
	for (;;) {
		int r;

		CZ(BN_rand(p, size, 1, 1));
		CZ(BN_set_bit(p, 1));
		r = BN_is_prime_fasttest(p, BN_prime_checks, 0, bnctx, 0, 1);
		if (r > 0) {
			RETURN(MAKWA_OK);
		} else if (r < 0) {
			RETURN(MAKWA_RAND_ERROR);
		}
	}

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	return err;
}

/* see makwa.h */
int
makwa_generate_key(int size, void *key, size_t *key_len)
{
	BIGNUM *p, *q; 
	int sp, sq;
	size_t len, u, off;
	unsigned char *buf;
	int err;

	p = NULL;
	q = NULL;
	if (size < 1273 || size > 32768) {
		RETURN(MAKWA_TOOLARGE);
	}
	sp = (size + 1) >> 1;
	sq = size - sp;
	len = 8 + (((size_t)sp + 7) >> 3) + (((size_t)sq + 7) >> 3);
	DO_BUFFER(key, key_len, len);

	CZ(p = BN_new());
	CZ(q = BN_new());
	CF(rand_prime(sp, p));
	CF(rand_prime(sq, q));

	buf = key;
	encode_32(buf, MAGIC_PRIVKEY);
	off = 4;
	u = len - off;
	CF(encode_mpi(p, buf + off, &u));
	off += u;
	CF(encode_mpi(q, buf + off, &u));
	off += u;

FUNCTION_EXIT:
	FREE_BN(p);
	FREE_BN(q);
	return err;
}

/*
 * Context internal contents.
 *
 * The BIGNUM fields are allocated in makwa_init_full(), and reused when
 * possible; they are finally released by makwa_free(). If
 * initialization fails, it is possible that the fields are only
 * partially initialized; this is supported (both makwa_init_full() and
 * makwa_free() can recover, without leaking memory).
 *
 * When using a private key, makwa_init_full() ensures that p is greater
 * than q (the factors are swapped if necessary).
 */
struct makwa_context_ {
	/* The modulus. */
	BIGNUM *modulus;

	/* The private key parameters; NULL if no private key is set. */
	BIGNUM *p, *q, *iq;

	/* The modulus length, in bytes. */
	size_t mod_len;

	/* The modulus checksum, used for the first 11 characters of the
	   string encoding of Makwa output. */
	unsigned char modID[8];

	/* The underlying hash function. */
	int hash_function;

	/* Default pre-hashing flag (when using the simple API). */
	int default_pre_hash;

	/* Default post-hashing flag and length (when using the simple API). */
	size_t default_post_hash_length;

	/* Default work factor (when using the simple API). */
	long default_work_factor;
};

/* see makwa.h */
makwa_context *
makwa_new(void)
{
	makwa_context *ctx;

	ctx = malloc(sizeof *ctx);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->modulus = NULL;
	ctx->p = NULL;
	ctx->q = NULL;
	ctx->iq = NULL;
	return ctx;
}

/* see makwa.h */
void
makwa_free(makwa_context *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->modulus != NULL) {
		BN_free(ctx->modulus);
	}
	if (ctx->p != NULL) {
		BN_clear_free(ctx->p);
	}
	if (ctx->q != NULL) {
		BN_clear_free(ctx->q);
	}
	if (ctx->iq != NULL) {
		BN_clear_free(ctx->iq);
	}
	free(ctx);
}

/*
 * Split a work factor into its mantissa (2 or 3) and logarithm. For
 * instance, if 'wf' is 384, then mantissa is 3 and the logarithm is 7,
 * because 384 is equal to 3 times 128 (which is 2 to the power 7).
 * If 'mant' is not NULL, then the mantissa is written into '*mant'.
 * If the work factor cannot be split, then MAKWA_BADPARAM is returned.
 */
static int
wflog(long wf, int *mant)
{
	int j;

	j = 0;
	while (wf > 3 && (wf & 1) == 0) {
		wf >>= 1;
		j ++;
	}
	if (wf != 2 && wf != 3) {
		return MAKWA_BADPARAM;
	}
	if (j > 99) {
		/*
		 * This one cannot happen with today's systems; it would
		 * require a 'long' type of more than 102 bits.
		 */
		return MAKWA_BADPARAM;
	}
	if (mant != NULL) {
		*mant = (int)wf;
	}
	return j;
}

/* see makwa.h */
int
makwa_init(makwa_context *ctx,
	const void *param, size_t param_len,
	int hash_function)
{
	return makwa_init_full(ctx, param, param_len, hash_function, 0, 0, 0);
}

/* see makwa.h */
int
makwa_init_full(makwa_context *ctx,
	const void *param, size_t param_len,
	int hash_function, int default_pre_hash,
	size_t default_post_hash_length, long default_work_factor)
{
	const unsigned char *buf;
	size_t off;
	int ret;
	unsigned long magic;
	unsigned char *tmp_mod;
	int deleg;
	BN_CTX *bnctx;
	int err;

	bnctx = NULL;
	tmp_mod = NULL;
	if (ctx->modulus == NULL) {
		CZ(ctx->modulus = BN_new());
	}

	/*
	 * Decode parameters. They may be either a public modulus, or
	 * a private key.
	 */
	if (param_len < 4) {
		RETURN(MAKWA_BADPARAM);
	}
	magic = decode_32(param, 0);
	buf = param;
	off = 4;
	deleg = 0;
	switch (magic) {
	case MAGIC_DELEG_PARAM:
		deleg = 1;
		/* fall through */
	case MAGIC_PUBKEY:
		/* Public modulus or delegation parameters. When decoding
		   delegation parameters, we just extract the modulus,
		   and ignore the rest. */
		CF(decode_mpi(buf, &off, param_len, ctx->modulus));
		if (!deleg && off != param_len) {
			RETURN(MAKWA_BADPARAM);
		}
		if (!BN_is_bit_set(ctx->modulus, 0)
			|| BN_is_bit_set(ctx->modulus, 1))
		{
			RETURN(MAKWA_BADPARAM);
		}
		FREE_BN(ctx->p);
		ctx->p = NULL;
		FREE_BN(ctx->q);
		ctx->q = NULL;
		FREE_BN(ctx->iq);
		ctx->iq = NULL;
		break;
	case MAGIC_PRIVKEY:
		/* Private key. */
		if (ctx->p == NULL) {
			CZ(ctx->p = BN_new());
		}
		if (ctx->q == NULL) {
			CZ(ctx->q = BN_new());
		}
		if (ctx->iq == NULL) {
			CZ(ctx->iq = BN_new());
		}
		CF(decode_mpi(buf, &off, param_len, ctx->p));
		CF(decode_mpi(buf, &off, param_len, ctx->q));
		if (off != param_len) {
			RETURN(MAKWA_BADPARAM);
		}

		/* We want p to be the greater of the two factors. */
		ret = BN_cmp(ctx->p, ctx->q);
		if (ret < 0) {
			BIGNUM *t;

			t = ctx->p;
			ctx->p = ctx->q;
			ctx->q = t;
		} else if (ret == 0) {
			RETURN(MAKWA_BADPARAM);
		}
		if (!BN_is_bit_set(ctx->p, 0)
			|| !BN_is_bit_set(ctx->p, 1)
			|| !BN_is_bit_set(ctx->q, 0)
			|| !BN_is_bit_set(ctx->q, 1))
		{
			RETURN(MAKWA_BADPARAM);
		}
		CZ(bnctx = BN_CTX_new());
		CZ(BN_mul(ctx->modulus, ctx->p, ctx->q, bnctx));
		CZX(BN_mod_inverse(ctx->iq, ctx->q, ctx->p, bnctx),
			MAKWA_BADPARAM);
		break;
	default:
		RETURN(MAKWA_BADPARAM);
	}
	ctx->mod_len = BN_num_bytes(ctx->modulus);
	if (ctx->mod_len < 160) {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * Set/check hash function.
	 */
	if (hash_function == 0) {
		hash_function = MAKWA_SHA256;
	} else {
		switch (hash_function) {
		case MAKWA_SHA256:
		case MAKWA_SHA512:
			break;
		default:
			RETURN(MAKWA_BADPARAM);
		}
	}
	ctx->hash_function = hash_function;

	/*
	 * Compute modulus ID.
	 */
	CZ(tmp_mod = malloc(ctx->mod_len));
	BN_bn2bin(ctx->modulus, tmp_mod);
	CF(makwa_kdf(hash_function, tmp_mod,
		ctx->mod_len, ctx->modID, sizeof ctx->modID));

	/*
	 * Set extra parameters (default values for the "simple API").
	 */
	ctx->default_pre_hash = default_pre_hash;
	if (default_post_hash_length > 0 && default_post_hash_length < 10) {
		RETURN(MAKWA_BADPARAM);
	}
	ctx->default_post_hash_length = default_post_hash_length;
	if (default_work_factor == 0) {
		default_work_factor = 4096;
	} else if (default_work_factor < 0) {
		RETURN(MAKWA_BADPARAM);
	} else if (wflog(default_work_factor, NULL) < 0) {
		RETURN(MAKWA_BADPARAM);
	}
	ctx->default_work_factor = default_work_factor;

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE(tmp_mod);
	return err;
}

/* see makwa.h */
int
makwa_export_public(const makwa_context *ctx, void *out, size_t *out_len)
{
	int err;

	DO_BUFFER(out, out_len, ctx->mod_len + 6);
	encode_32(out, MAGIC_PUBKEY);
	CF(encode_mpi(ctx->modulus, (unsigned char *)out + 4, NULL));

FUNCTION_EXIT:
	return err;
}

/* see makwa.h */
int
makwa_compute_modulus(
	const void *key, size_t key_len, void *mod, size_t *mod_len)
{
	makwa_context *mc;
	int err;

	mc = NULL;
	CZ(mc = makwa_new());
	CF(makwa_init(mc, key, key_len, 0));
	CF(makwa_export_public(mc, mod, mod_len));

FUNCTION_EXIT:
	makwa_free(mc);
	return err;
}

/*
 * Convert an integer into a sequence of bytes. The resulting sequence
 * has the provided length k (nominally, the length of the modulus).
 */
static int
I2OSP_ex(size_t k, BIGNUM *v, void *dst)
{
	unsigned char *buf;
	size_t len;

	buf = dst;
	len = BN_num_bytes(v);
	if (len > k) {
		return MAKWA_TOOLARGE;
	} else if (len < k) {
		memset(buf, 0, k - len);
		buf += k - len;
	}
	BN_bn2bin(v, buf);
	return MAKWA_OK;
}

/*
 * Convert an integer into a sequence of bytes. The resulting sequence
 * has the same length as the modulus.
 */
static int
I2OSP(const makwa_context *ctx, BIGNUM *v, void *dst)
{
	return I2OSP_ex(ctx->mod_len, v, dst);
}

/*
 * Convert a sequence of bytes into an integer; the source sequence
 * has the same length as the modulus. The resulting integer is
 * verified to be in the 1..n-1 range.
 */
static int
OS2IP(const makwa_context *ctx, const void *src, BIGNUM *v)
{
	size_t k;

	k = ctx->mod_len;
	if (BN_bin2bn(src, k, v) == NULL) {
		return MAKWA_NOMEM;
	}
	if (BN_is_zero(v) || BN_cmp(ctx->modulus, v) <= 0) {
		return MAKWA_BADPARAM;
	}
	return MAKWA_OK;
}

/*
 * Apply a sequence of squarings to a modular integer 'x'. The context
 * must contain a private key; the "fast path" is used. Beware that
 * this function only accepts positive 'w'.
 */
static int
multi_square_CRT(const makwa_context *ctx, BIGNUM *x, long w)
{
	BN_CTX *bnctx;
	BIGNUM *p, *q, *iq;
	BIGNUM *xp, *xq, *ep, *eq, *b2, *bw;
	BIGNUM *temps[6];
	int i, err;

	bnctx = NULL;
	p = ctx->p;
	q = ctx->q;
	iq = ctx->iq;
	for (i = 0; i < 6; i ++) {
		temps[i] = NULL;
	}
	for (i = 0; i < 6; i ++) {
		CZ(temps[i] = BN_new());
	}
	xp = temps[0];
	xq = temps[1];
	ep = temps[2];
	eq = temps[3];
	b2 = temps[4];
	bw = temps[5];
	CZ(bnctx = BN_CTX_new());

	CZ(BN_set_word(b2, 2));
	CZ(BN_set_word(bw, w));
	CZ(BN_copy(xp, p));
	CZ(BN_sub_word(xp, 1));
	CZ(BN_mod_exp(ep, b2, bw, xp, bnctx));
	CZ(BN_copy(xq, q));
	CZ(BN_sub_word(xq, 1));
	CZ(BN_mod_exp(eq, b2, bw, xq, bnctx));
	CZ(BN_mod(xp, x, p, bnctx));
	CZ(BN_mod(xq, x, q, bnctx));
	CZ(BN_mod_exp(xp, xp, ep, p, bnctx));
	CZ(BN_mod_exp(xq, xq, eq, q, bnctx));
	CZ(BN_mod_sub(b2, xp, xq, p, bnctx));
	CZ(BN_mod_mul(b2, b2, iq, p, bnctx));
	CZ(BN_mul(b2, b2, q, bnctx));
	CZ(BN_add(x, xq, b2));

FUNCTION_EXIT:
	for (i = 0; i < 6; i ++) {
		FREE_BN(temps[i]);
	}
	FREE_BNCTX(bnctx);
	return err;
}

/*
 * Revert a sequence of squarings on an integer 'x'. This function returns
 * the 'reverted' value modulo p and modulo q, in xp and xq. 'nw' contains
 * the number of squarings to revert (i.e. it is a nonnegative integer).
 */
static int
revert_multi_square(const makwa_context *ctx,
	BIGNUM *x, long nw, BIGNUM *xp, BIGNUM *xq)
{
	BN_CTX *bnctx;
	BIGNUM *p, *q;
	BIGNUM *ep, *eq, *bw;
	BIGNUM *temps[3];
	int i, err;

	bnctx = NULL;
	p = ctx->p;
	q = ctx->q;
	for (i = 0; i < 3; i ++) {
		temps[i] = NULL;
	}
	for (i = 0; i < 3; i ++) {
		CZ(temps[i] = BN_new());
	}
	ep = temps[0];
	eq = temps[1];
	bw = temps[2];
	CZ(bnctx = BN_CTX_new());

	CZ(BN_set_word(bw, nw));

	/* Compute the e'_p exponent. */
	CZ(BN_copy(ep, p));
	CZ(BN_add_word(ep, 1));
	CZ(BN_rshift(ep, ep, 2));
	CZ(BN_copy(xp, p));
	CZ(BN_sub_word(xp, 1));
	CZ(BN_mod_exp(ep, ep, bw, xp, bnctx));

	/* Compute the e'_q exponent. */
	CZ(BN_copy(eq, q));
	CZ(BN_add_word(eq, 1));
	CZ(BN_rshift(eq, eq, 2));
	CZ(BN_copy(xq, q));
	CZ(BN_sub_word(xq, 1));
	CZ(BN_mod_exp(eq, eq, bw, xq, bnctx));

	/* Do the exponentiations. */
	CZ(BN_mod(xp, x, p, bnctx));
	CZ(BN_mod(xq, x, q, bnctx));
	CZ(BN_mod_exp(xp, xp, ep, p, bnctx));
	CZ(BN_mod_exp(xq, xq, eq, q, bnctx));

FUNCTION_EXIT:
	for (i = 0; i < 3; i ++) {
		FREE_BN(temps[i]);
	}
	FREE_BNCTX(bnctx);
	return err;
}

/*
 * Apply the CRT.
 */
static int
apply_CRT(const makwa_context *ctx, BIGNUM *xp, BIGNUM *xq, BIGNUM *x)
{
	BN_CTX *bnctx;
	BIGNUM *p, *q, *iq, *t;
	int err;

	t = NULL;
	bnctx = NULL;
	CZ(t = BN_new());
	CZ(bnctx = BN_CTX_new());
	p = ctx->p;
	q = ctx->q;
	iq = ctx->iq;
	CZ(BN_mod_sub(t, xp, xq, p, bnctx));
	CZ(BN_mod_mul(t, t, iq, p, bnctx));
	CZ(BN_mul(t, t, q, bnctx));
	CZ(BN_add(x, xq, t));

FUNCTION_EXIT:
	FREE_BN(t);
	FREE_BNCTX(bnctx);
	return err;
}

/*
 * Apply a sequence of squarings to an integer 'x' modulo 'n'. This
 * function is context-free.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
static int
multi_square_cf(BIGNUM *x, unsigned long w, BIGNUM *n)
{
	BN_CTX *bnctx;
	BN_MONT_CTX *mctx;
	int err;

	bnctx = NULL;
	mctx = NULL;
	CZ(bnctx = BN_CTX_new());
	CZ(mctx = BN_MONT_CTX_new());
	CZ(BN_MONT_CTX_set(mctx, n, bnctx));
	CZ(BN_to_montgomery(x, x, mctx, bnctx));
	while (w -- > 0) {
		CZ(BN_mod_mul_montgomery(x, x, x, mctx, bnctx));
	}
	CZ(BN_from_montgomery(x, x, mctx, bnctx));

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE_MCTX(mctx);
	return err;
}

/*
 * Apply a sequence of squarings to a modular integer 'x'. If the context
 * contains a private key and the number of squarings is large enough to
 * make it worth, the "fast path" is used. If the 'w' parameter is negative,
 * then a private key MUST be known.
 */
static int
multi_square(const makwa_context *ctx, BIGNUM *x, long w)
{
	BIGNUM *xp, *xq;
	int err;
	int has_private;

	xp = NULL;
	xq = NULL;
	has_private = ctx->p != NULL && ctx->q != NULL && ctx->iq != NULL;

	/*
	 * For a negative count, we must apply the private key.
	 */
	if (w < 0) {
		/*
		 * We reject the case w == LONG_MIN because on most systems,
		 * -LONG_MIN is an overflow and goes back to LONG_MIN, i.e.
		 * negative. You cannot get such a difference from two
		 * nonnegative work factors which fit in a 'long' value
		 * anyway.
		 */
#if -LONG_MAX != LONG_MIN
		if (w == LONG_MIN) {
			RETURN(MAKWA_TOOLARGE);
		}
#endif
		if (!has_private) {
			RETURN(MAKWA_NO_PRIVATE_KEY);
		}
		CZ(xp = BN_new());
		CZ(xq = BN_new());
		CF(revert_multi_square(ctx, x, -w, xp, xq));
		CF(apply_CRT(ctx, xp, xq, x));
		RETURN(MAKWA_OK);
	}

	/*
	 * If there is a private key, and the square count is at least
	 * equal to about 34% of the modulus length (in bits), then it
	 * is worthwhile to switch to the "fast path".
	 */
	if (has_private) {
		long thr;

		thr = (((long)BN_num_bits(ctx->modulus) * 34) + 50) / 100;
		if (w > thr) {
			CF(multi_square_CRT(ctx, x, w));
			RETURN(MAKWA_OK);
		}
	}

	/*
	 * Normal path. We convert the integer to Montgomery representation,
	 * then square repeatedly with Montgomery multiplication.
	 */
	CF(multi_square_cf(x, (unsigned long)w, ctx->modulus));

FUNCTION_EXIT:
	FREE_BN(xp);
	FREE_BN(xq);
	return err;
}

/* see makwa.h */
int
makwa_hash(const makwa_context *ctx,
	const void *input, size_t input_len,
	const void *salt, size_t salt_len,
	int pre_hash,
	size_t post_hash_length,
	long work_factor,
	void *out, size_t *out_len)
{
	const unsigned char *pi;
	size_t k, u, blen;
	unsigned char tmp_pi[64];
	unsigned char *Xbuf, *tmp;
	BIGNUM *x;
	int err;

	Xbuf = NULL;
	tmp = NULL;
	x = NULL;

	/* 1. Filter out error conditions on input parameters. */
	k = ctx->mod_len;
	if (!pre_hash && (input_len > (k - 32) || input_len > 255)) {
		RETURN(MAKWA_TOOLARGE);
	}

	/* 2. Check and/or return output buffer size. */
	blen = (post_hash_length > 0) ? post_hash_length : k;
	DO_BUFFER(out, out_len, blen);

	/* 3. Output buffer is present and large enough; compute the
	      hash value. */
	/* Pre-hashing (if applicable). */
	if (pre_hash) {
		CF(makwa_kdf(ctx->hash_function,
			input, input_len, tmp_pi, 64));
		pi = tmp_pi;
		u = 64;
	} else {
		pi = input;
		u = input_len;
	}

	/* Allocate and fill Xbuf[] (padding computation). */
	CZ(Xbuf = malloc(k));
	memset(Xbuf, 0, k);
	CZ(tmp = malloc(salt_len + u + 1));
	memcpy(tmp, salt, salt_len);
	memcpy(tmp + salt_len, pi, u);
	tmp[salt_len + u] = u;
	CF(makwa_kdf(ctx->hash_function, tmp, salt_len + u + 1,
		Xbuf + 1, k - u - 2));
	free(tmp);
	tmp = NULL;
	memcpy(Xbuf + (k - u - 1), pi, u);
	Xbuf[k - 1] = u;

	/* Decode X[] into integer x. */
	CZ(x = BN_new());
	CF(OS2IP(ctx, Xbuf, x));

	/* Compute all the squarings. There is a corner case in which
	   the "+1" makes the work factor overflow; we handle that case
	   by calling multi_square() twice in that case. */
	if (work_factor == LONG_MAX) {
		CF(multi_square(ctx, x, work_factor));
		CF(multi_square(ctx, x, 1));
	} else {
		CF(multi_square(ctx, x, work_factor + 1));
	}

	/* Encode the result back into XBuf[]; this is the primary output. */
	CF(I2OSP(ctx, x, Xbuf));

	/* Return the primary output, or apply post-hashing, depending on
	   the parameters. */
	if (post_hash_length == 0) {
		memcpy(out, Xbuf, k);
	} else {
		CF(makwa_kdf(ctx->hash_function,
			Xbuf, k, out, post_hash_length));
	}

FUNCTION_EXIT:
	FREE(Xbuf);
	FREE(tmp);
	FREE_BN(x);
	return err;
}

/* see makwa.h */
int
makwa_change_work_factor(const makwa_context *ctx,
	void *out, size_t out_len, long diff_wf)
{
	BIGNUM *x;
	int err;

	x = NULL;
	if (out_len != ctx->mod_len) {
		RETURN(MAKWA_BADPARAM);
	}
	CZ(x = BN_new());
	CF(OS2IP(ctx, out, x));
	CF(multi_square(ctx, x, diff_wf));
	CF(I2OSP(ctx, x, out));

FUNCTION_EXIT:
	FREE_BN(x);
	return err;
}

/* see makwa.h */
int
makwa_unescrow(const makwa_context *ctx,
	const void *salt, size_t salt_len,
	long work_factor, void *out, size_t *out_len)
{
	size_t k;
	BN_CTX *bnctx;
	BIGNUM *x, *xp, *xq;
	BIGNUM *temp[7];
	int i, err;
	unsigned char *unesc;
	unsigned char *buf;

	/* Allocate temporaries. */
	bnctx = NULL;
	unesc = NULL;
	buf = NULL;
	for (i = 0; i < 7; i ++) {
		temp[i] = NULL;
	}
	for (i = 0; i < 7; i ++) {
		CZ(temp[i] = BN_new());
	}
	x = temp[4];
	xp = temp[5];
	xq = temp[6];
	CZ(bnctx = BN_CTX_new());

	/* Check input parameters and convert Makwa output to an integer. */
	k = ctx->mod_len;
	if (*out_len != k) {
		RETURN(MAKWA_BADPARAM);
	}
	if (work_factor < 0) {
		RETURN(MAKWA_BADPARAM);
	}
	if (work_factor == LONG_MAX) {
		/*
		 * This work factor value would overflow the count (because
		 * of the "+1") so we reject it. It does not make practical
		 * sense anyway: it is too large to be used without the
		 * "fast path".
		 *
		 * (If we really want to handle it, then we could copy
		 * the value to a temporary buffer and apply a work factor
		 * decrease on it).
		 */
		RETURN(MAKWA_TOOLARGE);
	}
	CF(OS2IP(ctx, out, x));

	/* Revert the squarings, yielding candidates x_p and x_q. */
	CF(revert_multi_square(ctx, x, work_factor + 1, xp, xq));

	/*
	 * Build all four candidates for x.
	 */
	CF(apply_CRT(ctx, xp, xq, temp[0]));
	CZ(BN_mod_sub(xp, ctx->p, xp, ctx->p, bnctx));
	CF(apply_CRT(ctx, xp, xq, temp[1]));
	CZ(BN_mod_sub(xq, ctx->q, xq, ctx->q, bnctx));
	CF(apply_CRT(ctx, xp, xq, temp[2]));
	CZ(BN_mod_sub(xp, ctx->p, xp, ctx->p, bnctx));
	CF(apply_CRT(ctx, xp, xq, temp[3]));

	/* Check all candidates: for each of them, we extract and recompute
	   the padding. Checking for 30 bytes is sufficient. */
	CZ(unesc = malloc(k));
	for (i = 0;; i ++) {
		size_t u;
		unsigned char pad[30];

		if (i == 4) {
			/*
			 * All four candidates were checked; neither has
			 * the correct format.
			 */
			RETURN(MAKWA_UNESCROW_ERROR);
		}
		CF(I2OSP(ctx, temp[i], unesc));
		if (unesc[0] != 0x00) {
			continue;
		}
		u = unesc[k - 1];
		if (u > (k - 32)) {
			continue;
		}
		CZ(buf = malloc(salt_len + u + 1));
		memcpy(buf, salt, salt_len);
		memcpy(buf + salt_len, unesc + k - 1 - u, u + 1);
		CF(makwa_kdf(ctx->hash_function,
			buf, salt_len + u + 1, pad, sizeof pad));
		free(buf);
		buf = NULL;
		if (memcmp(unesc + 1, pad, sizeof pad) == 0) {
			memcpy(out, unesc + k - 1 - u, u);
			memset(out + u, 0, k - u);
			*out_len = u;
			break;
		}
	}

FUNCTION_EXIT:
	for (i = 0; i < 7; i ++) {
		FREE_BN(temp[i]);
	}
	FREE(unesc);
	FREE_BNCTX(bnctx);
	FREE(buf);
	return err;
}

/*
 * NOTE: all the Base64 support code in this file is for the Base64
 * variant as specified by Makwa (annex A.4.1). Namely:
 * -- there is no embedded newline;
 * -- non-Base64 characters (e.g. spaces) are not ignored/tolerated;
 * -- the padding '=' signs are not used.
 */

/*
 * Compute the length in characters for the Base64 encoding of a given
 * number of source bytes. WARNING: that length DOES NOT INCLUDE the
 * terminating zero.
 */
static size_t
b64_length(size_t data_len)
{
	size_t len, n;

	n = data_len / 3;
	len = n << 2;
	switch (data_len - 3 * n) {
	case 1:
		len += 2;
		break;
	case 2:
		len += 3;
		break;
	}
	return len;
}

static size_t
get_string_output_length(size_t salt_len, size_t out_len)
{
	/*
	 * Base64 of modulus ID: 11 chars.
	 * Flags: 4 chars.
	 * Separators: 3 chars.
	 * Final zero: 1 char.
	 */
	return 19 + b64_length(salt_len) + b64_length(out_len);
}

/* see makwa.h */
size_t
makwa_get_string_output_length(
	const makwa_context *ctx, size_t salt_len, size_t post_hash_length)
{
	size_t out_len;

	if (post_hash_length == 0) {
		out_len = ctx->mod_len;
	} else {
		out_len = post_hash_length;
	}
	return get_string_output_length(salt_len, out_len);
}

/*
 * Base64-encode some bytes. The output buffer is assumed to be large
 * enough. The returned string is zero-terminated. The length of the
 * produced string is returned, EXCLUDING the terminating zero.
 */
static size_t
b64_encode(const void *src, size_t src_len, void *dst)
{
	const unsigned char *in;
	char *out;
	size_t out_len;
	unsigned v;

	static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz0123456789+/";

	in = src;
	out = dst;
	out_len = 0;
	while (src_len >= 3) {
		v = *in ++;
		*out ++ = B64[v >> 2];
		v = (v << 8) | *in ++;
		*out ++ = B64[(v >> 4) & 0x3F];
		v = (v << 8) | *in ++;
		*out ++ = B64[(v >> 6) & 0x3F];
		*out ++ = B64[v & 0x3F];
		src_len -= 3;
		out_len += 4;
	}
	switch (src_len) {
	case 1:
		v = *in ++;
		*out ++ = B64[v >> 2];
		*out ++ = B64[(v << 4) & 0x3F];
		out_len += 2;
		break;
	case 2:
		v = *in ++;
		*out ++ = B64[v >> 2];
		v = (v << 8) | *in ++;
		*out ++ = B64[(v >> 4) & 0x3F];
		*out ++ = B64[(v << 2) & 0x3F];
		out_len += 3;
		break;
	}
	*out = 0;
	return out_len;
}

/*
 * Base64-decode some characters. Decoding stops at the first non-Base64
 * character, or when src_len characters have been processed, whichever
 * comes first. The number of decoded bytes is returned.
 *
 * This function does NOT check for pending non-zero bits.
 */
static size_t
b64_decode(const void *src, size_t src_len, void *dst)
{
	const char *in;
	unsigned char *out;
	size_t out_len;
	unsigned acc, acc_num;

	in = src;
	out = dst;
	out_len = 0;
	acc = 0;
	acc_num = 0;
	while (src_len > 0) {
		unsigned c;

		c = *in ++;
		src_len --;
		if (c >= 'A' && c <= 'Z') {
			c -= 'A';
		} else if (c >= 'a' && c <= 'z') {
			c -= ('a' - 26);
		} else if (c >= '0' && c <= '9') {
			c -= ('0' - 52);
		} else if (c == '+') {
			c = 62;
		} else if (c == '/') {
			c = 63;
		} else {
			break;
		}
		acc = (acc << 6) | c;
		acc_num += 6;
		if (acc_num >= 8) {
			*out ++ = (acc >> (acc_num - 8)) & 0xFF;
			out_len ++;
			acc_num -= 8;
		}
	}
	return out_len;
}

/*
 * Mock decoding: this function is similar to b64_decode(), except that
 * it does not write the decoded bytes anywhere. It simply returns the
 * number of bytes that b64_decode() would decode.
 */
static size_t
b64_ahead(const void *src, size_t src_len)
{
	const char *in;
	size_t zlen;
	unsigned low;

	in = src;
	zlen = 0;
	low = 0;
	while (src_len > 0) {
		int c;

		c = *in ++;
		src_len --;
		if ((c >= 'A' && c <= 'Z')
			|| (c >= 'a' && c <= 'z')
			|| (c >= '0' && c <= '9')
			|| c == '+' || c == '/')
		{
			low += 6;
			if (low >= 8) {
				low &= 7;
				zlen ++;
			}
		} else {
			break;
		}
	}
	return zlen;
}

static int
encode_string_inner(const unsigned char *modID, size_t mod_len,
	const void *salt, size_t salt_len,
	int pre_hash,
	size_t post_hash_length,
	long work_factor,
	const void *bin_out,
	char *str_out, size_t *str_out_len)
{
	size_t u, clen, bin_out_len, off;
	int wfl, wfm;
	int err;

	/*
	 * Verify input parameters. We also don't want our computations
	 * to overflow, so we require that the salt and binary output
	 * lengths remain no longer than half the maximum value in a size_t,
	 * and we require the same for their sum.
	 * 
	 * Make sure that the parameters don't make our integers overflow.
	 */
	if (((salt_len << 1) >> 1) != salt_len
		|| ((post_hash_length << 1) >> 1) != post_hash_length)
	{
		RETURN(MAKWA_BADPARAM);
	}
	u = salt_len + post_hash_length;
	if (((u << 1) >> 1) != u) {
		RETURN(MAKWA_BADPARAM);
	}
	CF(wfl = wflog(work_factor, &wfm));
	if (post_hash_length > 0 && post_hash_length < 10) {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * Compute string output length; check it or return it.
	 */
	bin_out_len = (post_hash_length > 0) ? post_hash_length : mod_len;
	clen = get_string_output_length(salt_len, bin_out_len);
	DO_BUFFER(str_out, str_out_len, clen);

	/*
	 * The buffer is present and large enough; let's encode.
	 */
	off = 0;
	off += b64_encode(modID, 8, str_out + off);
	str_out[off ++] = '_';
	if (pre_hash) {
		if (post_hash_length > 0) {
			str_out[off ++] = 'b';
		} else {
			str_out[off ++] = 'r';
		}
	} else {
		if (post_hash_length > 0) {
			str_out[off ++] = 's';
		} else {
			str_out[off ++] = 'n';
		}
	}
	str_out[off ++] = wfm + '0';
	str_out[off ++] = (wfl / 10) + '0';
	str_out[off ++] = (wfl % 10) + '0';
	str_out[off ++] = '_';
	off += b64_encode(salt, salt_len, str_out + off);
	str_out[off ++] = '_';
	off += b64_encode(bin_out, bin_out_len, str_out + off);
	str_out[off ++] = 0;

FUNCTION_EXIT:
	return err;
}

/* see makwa.h */
int
makwa_encode_string(const makwa_context *ctx,
	const void *salt, size_t salt_len,
	int pre_hash,
	size_t post_hash_length,
	long work_factor,
	const void *bin_out,
	char *str_out, size_t *str_out_len)
{
	return encode_string_inner(ctx->modID, ctx->mod_len,
		salt, salt_len, pre_hash, post_hash_length,
		work_factor, bin_out, str_out, str_out_len);
}

/* see makwa.h */
int
makwa_decode_string(const makwa_context *ctx,
	const char *str,
	void *salt, size_t *salt_len,
	int *pre_hash,
	size_t *post_hash_length,
	long *work_factor,
	void *out, size_t *out_len)
{
	unsigned char tmp[8];
	int preH, post_hash;
	int wfl;
	long wfm;
	int d;
	size_t b_salt_len, s_salt_len;
	size_t b_out_len, s_out_len;
	int err, delayed_err;

	delayed_err = 0;

	/*
	 * Decode modulus ID (8-byte checksum).
	 */
	if (b64_decode(str, 11, tmp) != 8) {
		RETURN(MAKWA_BADPARAM);
	}
	str += b64_length(8);
	if (memcmp(tmp, ctx->modID, sizeof tmp) != 0) {
		RETURN(MAKWA_BADPARAM);
	}
	if (*str ++ != '_') {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * The flags (pre-hashing, post-hashing, work factor).
	 */
	switch (*str ++) {
	case 'n':
		preH = 0;
		post_hash = 0;
		break;
	case 'r':
		preH = 1;
		post_hash = 0;
		break;
	case 's':
		preH = 0;
		post_hash = 1;
		break;
	case 'b':
		preH = 1;
		post_hash = 1;
		break;
	default:
		RETURN(MAKWA_BADPARAM);
	}
	if (pre_hash != NULL) {
		*pre_hash = preH;
	}
	switch (*str ++) {
	case '2':
		wfm = 2;
		break;
	case '3':
		wfm = 3;
		break;
	default:
		RETURN(MAKWA_BADPARAM);
	}
	d = *str ++;
	if (d < '0' || d > '9') {
		RETURN(MAKWA_BADPARAM);
	}
	wfl = d - '0';
	d = *str ++;
	if (d < '0' || d > '9') {
		RETURN(MAKWA_BADPARAM);
	}
	wfl = 10 * wfl + d - '0';
	if (*str ++ != '_') {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * We need to take care when computing the work factor: we may
	 * overflow, and C language does not guarantee behaviour in those
	 * cases.
	 */
	while (wfl > 0) {
		if (wfm > (LONG_MAX >> 1)) {
			RETURN(MAKWA_TOOLARGE);
		}
		wfm <<= 1;
		wfl --;
	}
	if (work_factor != NULL) {
		*work_factor = wfm;
	}

	/*
	 * The salt. Behaviour depends on whether the caller wants to
	 * retrieve the salt value or not. We do not use the DO_BUFFER
	 * macro because this function has two output buffers, and we
	 * want to be able to report both lengths.
	 */
	b_salt_len = b64_ahead(str, strlen(str));
	s_salt_len = b64_length(b_salt_len);
	if (salt == NULL) {
		if (salt_len != NULL) {
			*salt_len = b_salt_len;
		}
	} else {
		if (salt_len != NULL && *salt_len < b_salt_len) {
			*salt_len = b_salt_len;
			delayed_err = MAKWA_BUFFER_TOO_SMALL;
			salt = NULL;
			/* The salt buffer was too small but we must
			   keep on, because the caller may also be
			   interested in the output buffer length. */
		} else {
			b64_decode(str, s_salt_len, salt);
			if (salt_len != NULL) {
				*salt_len = b_salt_len;
			}
		}
	}
	str += s_salt_len;
	if (*str ++ != '_') {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * The output itself. If post-hashing is used, then the output
	 * length must encode at least 10 bytes; otherwise, the output
	 * must match that of the modulus.
	 */
	b_out_len = b64_ahead(str, strlen(str));
	s_out_len = b64_length(b_out_len);
	if (post_hash) {
		if (b_out_len < 10) {
			RETURN(MAKWA_BADPARAM);
		}
		if (post_hash_length != NULL) {
			*post_hash_length = b_out_len;
		}
	} else {
		if (b_out_len != ctx->mod_len) {
			RETURN(MAKWA_BADPARAM);
		}
		if (post_hash_length != NULL) {
			*post_hash_length = 0;
		}
	}
	if (out != NULL) {
		if (*out_len < b_out_len) {
			*out_len = b_out_len;
			RETURN(MAKWA_BUFFER_TOO_SMALL);
		}
		b64_decode(str, s_out_len, out);
	}
	if (out_len != NULL) {
		*out_len = b_out_len;
	}
	str += s_out_len;
	if (*str != 0) {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * All decoding proceeded correctly, except possibly a "too small
	 * buffer" error with the salt.
	 */
FUNCTION_EXIT:
	if (err == 0 && delayed_err < 0) {
		err = delayed_err;
	}
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_new(const makwa_context *ctx,
	const char *password, char *str_out, size_t *str_out_len)
{
	unsigned char salt[16], *tmp;
	size_t zlen, tmp_len;
	int err;

	tmp = NULL;

	/*
	 * We first check the output buffer length: an initial call with
	 * no output buffer must be fast.
	 */
	zlen = makwa_get_string_output_length(ctx,
		sizeof salt, ctx->default_post_hash_length);
	DO_BUFFER(str_out, str_out_len, zlen);

	/*
	 * Generate a new random salt.
	 */
	CF(makwa_make_new_salt(salt, sizeof salt));

	/*
	 * Generate the output into a temporary buffer.
	 */
	CF(makwa_hash(ctx, password, strlen(password),
		salt, sizeof salt, ctx->default_pre_hash,
		ctx->default_post_hash_length, ctx->default_work_factor,
		NULL, &tmp_len));
	CZ(tmp = malloc(tmp_len));
	CF(makwa_hash(ctx, password, strlen(password),
		salt, sizeof salt, ctx->default_pre_hash,
		ctx->default_post_hash_length, ctx->default_work_factor,
		tmp, &tmp_len));

	/*
	 * Encode the string. We already checked the buffer length.
	 */
	CF(makwa_encode_string(ctx,
		salt, sizeof salt, ctx->default_pre_hash,
		ctx->default_post_hash_length, ctx->default_work_factor,
		tmp, str_out, str_out_len));

FUNCTION_EXIT:
	FREE(tmp);
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_verify(const makwa_context *ctx,
	const char *password, const char *ref_str)
{
	void *salt;
	size_t salt_len;
	int pre_hash;
	size_t post_hash_length;
	long work_factor;
	void *ref, *out;
	size_t ref_len, out_len;
	int err;

	salt = NULL;
	ref = NULL;
	out = NULL;

	/*
	 * 1. Decode reference string, to obtain the binary output, and
	 *    also the parameters needed to recompute that output.
	 */
	CF(makwa_decode_string(ctx, ref_str, NULL, &salt_len,
		&pre_hash, &post_hash_length, &work_factor, NULL, &ref_len));
	if (salt_len > 0) {
		CZ(salt = malloc(salt_len));
	}
	CZ(ref = malloc(ref_len));
	CF(makwa_decode_string(ctx, ref_str, salt, &salt_len,
		&pre_hash, &post_hash_length, &work_factor, ref, &ref_len));

	/*
	 * 2. Recompute the hash into a temporary buffer. The output ought
	 *    to have the same length as the reference output length.
	 */
	out_len = ref_len;
	CZ(out = malloc(ref_len));
	CF(makwa_hash(ctx, password, strlen(password),
		salt, salt_len, pre_hash, post_hash_length, work_factor,
		out, &out_len));
	if (out_len != ref_len || memcmp(out, ref, ref_len) != 0) {
		RETURN(MAKWA_WRONG_PASSWORD);
	}

FUNCTION_EXIT:
	FREE(salt);
	FREE(ref);
	FREE(out);
	return err;
}

/* see makwa.h */
int
makwa_simple_reset_work_factor(const makwa_context *ctx,
	char *str, long new_work_factor)
{
	int err;
	size_t post_hash_length;
	long work_factor;
	size_t salt_len, out_len;
	unsigned char *out;
	int has_private;
	int wfl, wfm;

	out = NULL;
	CF(makwa_decode_string(ctx, str, NULL, &salt_len,
		NULL, &post_hash_length, &work_factor, NULL, &out_len));

	/* We cannot change the work factor if post-hashing was applied. */
	if (post_hash_length != 0) {
		RETURN(MAKWA_POST_HASH);
	}

	/* If the work factor is not actually changed, then we are
	   finished. */
	if (new_work_factor == work_factor) {
		RETURN(MAKWA_OK);
	}

	/* New work factor must be encodable. */
	if (new_work_factor < 0) {
		RETURN(MAKWA_BADPARAM);
	}
	CF(wfl = wflog(new_work_factor, &wfm));

	/* If we are decreasing the work factor, then we need a private
	   key. */
	has_private = ctx->p != NULL && ctx->q != NULL && ctx->iq != NULL;
	if (new_work_factor < work_factor && !has_private) {
		RETURN(MAKWA_NO_PRIVATE_KEY);
	}

	/* Get the binary output. */
	CZ(out = malloc(out_len));
	CF(makwa_decode_string(ctx, str, NULL, NULL,
		NULL, NULL, NULL, out, &out_len));

	/*
	 * Compute the work factor change. Since both work factors are
	 * in the positive 'long' range, the difference does not overflow.
	 */
	CF(makwa_change_work_factor(ctx, out, out_len,
		new_work_factor - work_factor));

	/*
	 * Now we just have to reencode the new work factor and output.
	 * Since the salt has not changed, we can put things back
	 * directly in the buffer at the "right place".
	 */
	str[13] = '0' + wfm;
	str[14] = '0' + (wfl / 10);
	str[15] = '0' + (wfl % 10);
	b64_encode(out, out_len, str + 18 + b64_length(salt_len));

FUNCTION_EXIT:
	FREE(out);
	return err;
}

/* see makwa.h */
int
makwa_simple_unescrow(const makwa_context *ctx, char *str)
{
	unsigned char *salt, *out;
	size_t salt_len, out_len;
	int pre_hash;
	size_t post_hash_length;
	long work_factor;
	int err;
	size_t u;

	salt = NULL;
	out = NULL;
	CF(makwa_decode_string(ctx, str, NULL, &salt_len, &pre_hash,
		&post_hash_length, &work_factor, NULL, &out_len));
	if (pre_hash) {
		RETURN(MAKWA_PRE_HASH);
	}
	if (post_hash_length > 0) {
		RETURN(MAKWA_POST_HASH);
	}
	CZ(salt = malloc(salt_len));
	CZ(out = malloc(out_len));
	CF(makwa_decode_string(ctx, str, salt, &salt_len, NULL,
		NULL, NULL, out, &out_len));
	CF(makwa_unescrow(ctx, salt, salt_len, work_factor, out, &out_len));
	for (u = 0; u < out_len; u ++) {
		if (out[u] == 0) {
			RETURN(MAKWA_EMBEDDED_ZERO);
		}
	}
	memcpy(str, out, out_len + 1);

FUNCTION_EXIT:
	FREE(salt);
	FREE(out);
	return err;
}

/* ====================================================================== */

struct makwa_delegation_parameters_ {
	BIGNUM *modulus;
	long work_factor;
	size_t num;
	BIGNUM **alpha;
	BIGNUM **beta;
};

/* see makwa.h */
int
makwa_delegation_generate(const void *param, size_t param_len,
	long work_factor, void *out, size_t *out_len)
{
	BN_CTX *bnctx;
	makwa_context *mc;
	unsigned char *buf;
	size_t len, mlen, off, u, num;
	BIGNUM *z;
	int err;

	bnctx = NULL;
	mc = NULL;
	z = NULL;
	if (work_factor < 0) {
		RETURN(MAKWA_BADPARAM);
	}

	/* As per the specification recommendations, we always generate
	   300 mask pairs. */
	num = 300;

	CZ(mc = makwa_new());
	CF(makwa_init(mc, param, param_len, 0));
	mlen = mpi_length(mc->modulus);
	DO_BUFFER(out, out_len, 10 + (2 * num + 1) * mlen);

	CZ(bnctx = BN_CTX_new());
	CZ(z = BN_new());

	buf = out;
	encode_32(buf, MAGIC_DELEG_PARAM);
	off = 4;
	len = mlen;
	CF(encode_mpi(mc->modulus, buf + off, &len));
	off += len;
	encode_32(buf + off, work_factor);
	off += 4;
	encode_16(buf + off, num);
	off += 2;
	for (u = 0; u < num; u ++) {
		/*
		 * Each alpha value must be a quadratic residue, so we
		 * apply an initial squaring on the selected random value.
		 */
		do {
			CZ(BN_rand_range(z, mc->modulus));
		} while (BN_is_zero(z));
		CZ(BN_mod_mul(z, z, z, mc->modulus, bnctx));
		len = mlen;
		CF(encode_mpi(z, buf + off, &len));
		off += len;
		CF(multi_square(mc, z, work_factor));
		CZ(BN_mod_inverse(z, z, mc->modulus, bnctx));
		len = mlen;
		CF(encode_mpi(z, buf + off, &len));
		off += len;
	}
	if (out_len != NULL) {
		*out_len = off;
	}

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE_BN(z);
	makwa_free(mc);
	return err;
}

/* see makwa.h */
makwa_delegation_parameters *
makwa_delegation_new(void)
{
	makwa_delegation_parameters *mdp;

	mdp = malloc(sizeof *mdp);
	if (mdp == NULL) {
		return NULL;
	}
	mdp->modulus = NULL;
	mdp->work_factor = 0;
	mdp->num = 0;
	mdp->alpha = NULL;
	mdp->beta = NULL;
	return mdp;
}

static void
mdp_clear(makwa_delegation_parameters *mdp)
{
	FREE_BN(mdp->modulus);
	mdp->modulus = NULL;
	if (mdp->alpha != NULL) {
		size_t u;

		for (u = 0; u < mdp->num; u ++) {
			FREE_BN(mdp->alpha[u]);
		}
		free(mdp->alpha);
		mdp->alpha = NULL;
	}
	if (mdp->beta != NULL) {
		size_t u;

		for (u = 0; u < mdp->num; u ++) {
			FREE_BN(mdp->beta[u]);
		}
		free(mdp->beta);
		mdp->beta = NULL;
	}
	mdp->work_factor = 0;
	mdp->num = 0;
}

/* see makwa.h */
void
makwa_delegation_free(makwa_delegation_parameters *mdp)
{
	if (mdp == NULL) {
		return;
	}
	mdp_clear(mdp);
	free(mdp);
}

/* see makwa.h */
int
makwa_delegation_init(makwa_delegation_parameters *mdp,
	const void *param, size_t param_len)
{
	BN_CTX *bnctx;
	BN_MONT_CTX *mctx;
	size_t off;
	int err;
	unsigned long wf;
	size_t u;

	bnctx = NULL;
	mctx = NULL;
	CZ(bnctx = BN_CTX_new());
	CZ(mctx = BN_MONT_CTX_new());
	mdp_clear(mdp);
	if (param_len < 4 || decode_32(param, 0) != MAGIC_DELEG_PARAM) {
		RETURN(MAKWA_BADPARAM);
	}
	off = 4;
	CZ(mdp->modulus = BN_new());
	CF(decode_mpi(param, &off, param_len, mdp->modulus));
	if (BN_num_bytes(mdp->modulus) < 160
		|| !BN_is_bit_set(mdp->modulus, 0)
		|| BN_is_bit_set(mdp->modulus, 1))
	{
		RETURN(MAKWA_BADPARAM);
	}
	CZ(BN_MONT_CTX_set(mctx, mdp->modulus, bnctx));
	if (off + 6 > param_len) {
		RETURN(MAKWA_BADPARAM);
	}
	wf = decode_32(param, off);
	off += 4;
	if (wf > (unsigned long)LONG_MAX) {
		RETURN(MAKWA_BADPARAM);
	}
	mdp->work_factor = (long)wf;
	mdp->num = decode_16(param, off);
	off += 2;
	if (mdp->num == 0) {
		RETURN(MAKWA_BADPARAM);
	}
	CZ(mdp->alpha = malloc(mdp->num * sizeof *(mdp->alpha)));
	for (u = 0; u < mdp->num; u ++) {
		mdp->alpha[u] = NULL;
	}
	CZ(mdp->beta = malloc(mdp->num * sizeof *(mdp->beta)));
	for (u = 0; u < mdp->num; u ++) {
		mdp->beta[u] = NULL;
	}
	for (u = 0; u < mdp->num; u ++) {
		CZ(mdp->alpha[u] = BN_new());
		CZ(mdp->beta[u] = BN_new());
		CF(decode_mpi(param, &off, param_len, mdp->alpha[u]));
		CF(decode_mpi(param, &off, param_len, mdp->beta[u]));
		if (BN_is_zero(mdp->alpha[u])
			|| BN_cmp(mdp->modulus, mdp->alpha[u]) <= 0
			|| BN_is_zero(mdp->beta[u])
			|| BN_cmp(mdp->modulus, mdp->beta[u]) <= 0)
		{
			RETURN(MAKWA_BADPARAM);
		}
		/* We convert all pair elements to Montgomery
		   representation. */
		CZ(BN_to_montgomery(mdp->alpha[u], mdp->alpha[u], mctx, bnctx));
		CZ(BN_to_montgomery(mdp->beta[u], mdp->beta[u], mctx, bnctx));
	}

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE_MCTX(mctx);
	if (err != MAKWA_OK) {
		mdp_clear(mdp);
	}
	return err;
}

/* see makwa.h */
long
makwa_delegation_get_work_factor(const makwa_delegation_parameters *mdp)
{
	return mdp->work_factor;
}

/*
 * Using the delegation parameters, create a "mask pair". The caller must
 * put the value to mask in z. This function replaces z with the value to
 * send, and stores the "unmask" integer in 'unmask'.
 */
static int
create_mask_pair(const makwa_delegation_parameters *mdp,
	BIGNUM *z, BIGNUM *unmask)
{
	BN_CTX *bnctx;
	BN_MONT_CTX *mctx;
	unsigned char rnd[38];
	int err;
	size_t u, n;

	bnctx = NULL;
	mctx = NULL;
	if (!RAND_bytes(rnd, sizeof rnd)) {
		RETURN(MAKWA_RAND_ERROR);
	}
	CZ(bnctx = BN_CTX_new());
	CZ(mctx = BN_MONT_CTX_new());
	CZ(BN_MONT_CTX_set(mctx, mdp->modulus, bnctx));
	CZ(BN_to_montgomery(z, z, mctx, bnctx));
	CZ(BN_set_word(unmask, 1));
	CZ(BN_to_montgomery(unmask, unmask, mctx, bnctx));
	n = mdp->num;
	if (n > 300) {
		n = 300;
	}
	for (u = 0; u < n; u ++) {
		if (!((rnd[u >> 3] >> (u & 7)) & 1)) {
			continue;
		}
		CZ(BN_mod_mul_montgomery(
			z, z, mdp->alpha[u], mctx, bnctx));
		CZ(BN_mod_mul_montgomery(
			unmask, unmask, mdp->beta[u], mctx, bnctx));
	}
	CZ(BN_from_montgomery(z, z, mctx, bnctx));
	CZ(BN_from_montgomery(unmask, unmask, mctx, bnctx));

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE_MCTX(mctx);
	return err;
}

struct makwa_delegation_context_ {
	BIGNUM *modulus;
	unsigned char modID[8];
	int hash_function;
	BIGNUM *z;
	long work_factor;
	BIGNUM *unmask;
	int pre_hash;
	size_t post_hash_length;
	void *salt;
	size_t salt_len;
	void *ref_out;
	size_t ref_out_len;
};

/* see makwa.h */
makwa_delegation_context *
makwa_delegation_context_new(void)
{
	makwa_delegation_context *mdc;

	mdc = malloc(sizeof *mdc);
	if (mdc == NULL) {
		return NULL;
	}
	mdc->modulus = BN_new();
	mdc->z = BN_new();
	mdc->unmask = BN_new();
	mdc->hash_function = -1;
	mdc->salt = NULL;
	mdc->ref_out = NULL;
	if (mdc->modulus == NULL || mdc->z == NULL || mdc->unmask == NULL) {
		goto exit_oom;
	}
	return mdc;

exit_oom:
	makwa_delegation_context_free(mdc);
	return NULL;
}

/* see makwa.h */
void
makwa_delegation_context_free(makwa_delegation_context *mdc)
{
	if (mdc == NULL) {
		return;
	}
	FREE_BN(mdc->modulus);
	FREE_BN(mdc->z);
	FREE_BN(mdc->unmask);
	FREE(mdc->salt);
	FREE(mdc->ref_out);
	free(mdc);
}

/* see makwa.h */
int
makwa_hash_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	const void *input, size_t input_len,
	const void *salt, size_t salt_len,
	int pre_hash, size_t post_hash_length,
	makwa_delegation_context *mdc)
{
	int err;
	unsigned char *Xbuf;

	Xbuf = NULL;

	/*
	 * Verify that the delegation parameters use the same modulus
	 * as the context.
	 */
	if (BN_cmp(ctx->modulus, mdp->modulus) != 0) {
		RETURN(MAKWA_BADPARAM);
	}

	/*
	 * Hash with no post-hashing and a work factor 0; the
	 * output then is the value we want to mask and send.
	 */
	CZ(Xbuf = malloc(ctx->mod_len));
	CF(makwa_hash(ctx, input, input_len, salt, salt_len,
		pre_hash, 0, 0, Xbuf, NULL));
	CF(OS2IP(ctx, Xbuf, mdc->z));

	/*
	 * Now mask the value.
	 */
	CF(create_mask_pair(mdp, mdc->z, mdc->unmask));
	mdc->hash_function = ctx->hash_function;
	mdc->work_factor = mdp->work_factor;
	mdc->pre_hash = pre_hash;
	mdc->post_hash_length = post_hash_length;
	CZ(BN_copy(mdc->modulus, mdp->modulus));
	memcpy(mdc->modID, ctx->modID, 8);

	/*
	 * We need to keep a copy of the salt, in case a string-encoded
	 * output is required.
	 */
	FREE(mdc->salt);
	mdc->salt = NULL;
	if (salt_len > 0) {
		CZ(mdc->salt = malloc(salt_len));
		mdc->salt_len = salt_len;
		memcpy(mdc->salt, salt, salt_len);
	}
	FREE(mdc->ref_out);
	mdc->ref_out = NULL;

FUNCTION_EXIT:
	FREE(Xbuf);
	return err;
}

/* see makwa.h */
int
makwa_hash_delegate_end(const makwa_delegation_context *mdc,
	const void *ans, size_t ans_len,
	void *out, size_t *out_len)
{
	BN_CTX *bnctx;
	BIGNUM *z;
	size_t off, k, len;
	void *Zbuf;
	int err;

	bnctx = NULL;
	z = NULL;
	Zbuf = NULL;

	CZ(z = BN_new());

	/* Decode answer. */
	off = 0;
	if (ans_len < 4 || decode_32(ans, 0) != MAGIC_DELEG_ANS) {
		RETURN(MAKWA_BADPARAM);
	}
	off += 4;
	CF(decode_mpi(ans, &off, ans_len, z));
	if (BN_is_zero(z) || BN_cmp(mdc->modulus, z) <= 0) {
		RETURN(MAKWA_BADPARAM);
	}
	if (off != ans_len) {
		RETURN(MAKWA_BADPARAM);
	}

	/* Process output buffer semantics. */
	k = BN_num_bytes(mdc->modulus);
	len = (mdc->post_hash_length == 0) ? k : mdc->post_hash_length;
	DO_BUFFER(out, out_len, len);

	/* Unmask the integer. */
	CZ(bnctx = BN_CTX_new());
	CZ(BN_mod_mul(z, z, mdc->unmask, mdc->modulus, bnctx));

	/* Encode result; apply post-hashing if necessary. */
	if (mdc->post_hash_length == 0) {
		CF(I2OSP_ex(k, z, out));
	} else {
		CZ(Zbuf = malloc(k));
		CF(I2OSP_ex(k, z, Zbuf));
		CF(makwa_kdf(mdc->hash_function,
			Zbuf, k, out, mdc->post_hash_length));
	}

FUNCTION_EXIT:
	FREE_BNCTX(bnctx);
	FREE_BN(z);
	FREE(Zbuf);
	return err;
}

/* see makwa.h */
int
makwa_delegation_context_encode(
	const makwa_delegation_context *mdc, void *req, size_t *req_len)
{
	size_t len, mlen, zlen;
	unsigned char *buf;
	int err;

	mlen = mpi_length(mdc->modulus);
	zlen = mpi_length(mdc->z);
	len = 8 + mlen + zlen;
	DO_BUFFER(req, req_len, len);

	/*
	 * Since we take care to allow only "correct" values to reach our
	 * context structures, the MPI encoding functions below cannot
	 * fail.
	 */
	buf = req;
	encode_32(buf, MAGIC_DELEG_REQ);
	buf += 4;
	CF(encode_mpi(mdc->modulus, buf, &mlen));
	buf += mlen;
	encode_32(buf, mdc->work_factor);
	buf += 4;
	CF(encode_mpi(mdc->z, buf, &zlen));
	buf += zlen;

FUNCTION_EXIT:
	return err;
}

/* see makwa.h */
int
makwa_delegation_answer(
	const void *req, size_t req_len, void *ans, size_t *ans_len)
{
	BIGNUM *n, *z;
	size_t off, k;
	int err;
	unsigned long work_factor;
	unsigned char *buf;
	size_t buf_len;

	n = NULL;
	z = NULL;
	CZ(n = BN_new());
	CZ(z = BN_new());

	/* Decode request. */
	off = 0;
	if (req_len < 4 || decode_32(req, 0) != MAGIC_DELEG_REQ) {
		RETURN(MAKWA_BADPARAM);
	}
	off += 4;
	CF(decode_mpi(req, &off, req_len, n));
	if ((off + 4) > req_len) {
		RETURN(MAKWA_BADPARAM);
	}
	work_factor = decode_32(req, off);
	off += 4;
	CF(decode_mpi(req, &off, req_len, z));
	if (off != req_len) {
		RETURN(MAKWA_BADPARAM);
	}

	/* Verify request elements. */
	k = BN_num_bytes(n);
	if (k < 160) {
		RETURN(MAKWA_BADPARAM);
	}
	if (!BN_is_bit_set(n, 0) || BN_is_bit_set(n, 1)) {
		RETURN(MAKWA_BADPARAM);
	}
	if (BN_is_zero(z) || BN_cmp(n, z) <= 0) {
		RETURN(MAKWA_BADPARAM);
	}

	/* Handle the output buffer semantics. */
	DO_BUFFER(ans, ans_len, k + 6);

	/* Apply the squarings. */
	CF(multi_square_cf(z, work_factor, n));

	/* Encode the result. */
	buf = ans;
	encode_32(buf, MAGIC_DELEG_ANS);
	buf_len = k + 2;
	CF(encode_mpi(z, buf + 4, &buf_len));

FUNCTION_EXIT:
	FREE_BN(n);
	FREE_BN(z);
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_new_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	char *password, makwa_delegation_context *mdc)
{
	int err;
	unsigned char salt[16];

	CF(wflog(mdp->work_factor, NULL));
	CF(makwa_make_new_salt(salt, sizeof salt));
	CF(makwa_hash_delegate_begin(ctx, mdp,
		password, strlen(password),
		salt, sizeof salt, ctx->default_pre_hash,
		ctx->default_post_hash_length, mdc));

FUNCTION_EXIT:
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_verify_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	char *password, const char *ref, makwa_delegation_context *mdc)
{
	int err;
	void *salt, *ref_out;
	int pre_hash;
	size_t post_hash_length;
	long work_factor;
	size_t salt_len, ref_out_len;

	salt = NULL;
	ref_out = NULL;
	CF(wflog(mdp->work_factor, NULL));
	CF(makwa_decode_string(ctx, ref, NULL, &salt_len, &pre_hash,
		&post_hash_length, &work_factor, NULL, &ref_out_len));
	if (salt_len > 0) {
		CZ(salt = malloc(salt_len));
	}
	CZ(ref_out = malloc(ref_out_len));
	CF(makwa_decode_string(ctx, ref, salt, &salt_len, &pre_hash,
		&post_hash_length, &work_factor, ref_out, &ref_out_len));
	if (work_factor != mdp->work_factor) {
		RETURN(MAKWA_BADPARAM);
	}
	CF(makwa_hash_delegate_begin(ctx, mdp,
		password, strlen(password),
		salt, salt_len, pre_hash, post_hash_length, mdc));
	FREE(mdc->ref_out);
	mdc->ref_out = ref_out;
	mdc->ref_out_len = ref_out_len;
	ref_out = NULL;

FUNCTION_EXIT:
	FREE(salt);
	FREE(ref_out);
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_delegate_end(const makwa_delegation_context *mdc,
	const void *ans, size_t ans_len, void *str_out, size_t *str_out_len)
{
	int err;
	void *out;
	size_t out_len;

	out = NULL;
	out_len = mdc->post_hash_length == 0
		? (size_t)BN_num_bytes(mdc->modulus)
		: mdc->post_hash_length;
	DO_BUFFER(str_out, str_out_len,
		get_string_output_length(mdc->salt_len, out_len));

	CF(makwa_hash_delegate_end(mdc, ans, ans_len, NULL, &out_len));
	CZ(out = malloc(out_len));
	CF(makwa_hash_delegate_end(mdc, ans, ans_len, out, &out_len));

	CF(encode_string_inner(mdc->modID, BN_num_bytes(mdc->modulus),
		mdc->salt, mdc->salt_len, mdc->pre_hash,
		mdc->post_hash_length, mdc->work_factor,
		out, str_out, str_out_len));

FUNCTION_EXIT:
	FREE(out);
	return err;
}

/* see makwa.h */
int
makwa_simple_hash_verify_delegate_end(
	const makwa_delegation_context *mdc, const void *ans, size_t ans_len)
{
	int err;
	void *out;
	size_t out_len;

	out = NULL;
	if (mdc->ref_out == NULL) {
		/* No recorded output; the context was not initialized with
		   makwa_simple_hash_verify_delegate_begin(). */
		RETURN(MAKWA_BADPARAM);
	}
	CF(makwa_hash_delegate_end(mdc, ans, ans_len, NULL, &out_len));
	CZ(out = malloc(out_len));
	CF(makwa_hash_delegate_end(mdc, ans, ans_len, out, &out_len));
	if (out_len != mdc->ref_out_len
		|| memcmp(out, mdc->ref_out, out_len) != 0)
	{
		RETURN(MAKWA_WRONG_PASSWORD);
	}

FUNCTION_EXIT:
	FREE(out);
	return err;
}
