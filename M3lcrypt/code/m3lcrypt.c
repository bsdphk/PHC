/********************************************************************
 *
 *      FILE 	   :m3l_crypt.c
 *
 *      DATE	   :18/03/14
 *      VERSION	   :1.0
 *
 *      CONTENTS   :The M3l_crypt PBKDF reference implementation
 *	REFERENCES :Makwakwa, I., "The M3l_crypt_H PBKDF",
 * 		    PHC Competition Submission, March 2014 
 *
\********************************************************************/


#include "m3lcrypt.h" 

#if defined(__cplusplus)
extern "C"
{
#endif

void PHS
(
	void *out,			/* output buffer	*/
	size_t outlen,			/* output length	*/
	const void *in,			/* secret key	 	*/
	size_t inlen,			/* key length	 	*/
	void *salt,			/* salt		 	*/
	size_t saltlen,			/* salt length	 	*/
	unsigned int t_cost,		/* time cost	 	*/
	unsigned int m_cost		/* memory cost	 	*/
)
{
#if defined(_64BIT)
	uint64_t digest[DIGEST_SIZE >> 3];
	uint64_t shash[DIGEST_SIZE >> 3];
	uint64_t h[2*(DIGEST_SIZE >> 3)];
	uint64_t X[m_cost][DIGEST_SIZE >> 3];
	uint64_t V[_VSIZE][DIGEST_SIZE >> 3];
	int lword = (DIGEST_SIZE >> 3) - 1;
#else
	uint32_t digest[DIGEST_SIZE >> 2];
	uint32_t shash[DIGEST_SIZE >> 2];
	uint32_t h[2*(DIGEST_SIZE >> 2)];
	uint32_t X[m_cost][DIGEST_SIZE >> 2];
	uint32_t V[_VSIZE][DIGEST_SIZE >> 2];
	int lword = (DIGEST_SIZE >> 2) - 1;
#endif
	int isz  = sizeof(unsigned int);
	unsigned int k,i = 0,mask0 = m_cost-1,mask1 = _VSIZE-1;

	/* obtain H(in + ipad) and H(in + opad) */

	PRF_init((unsigned char *)h,(const unsigned char *)in,inlen);

	hash_ctx	ctx;

	ctx_reinit(&ctx,(unsigned char *)h);
	(*f_hash)((const unsigned char *)salt,saltlen,&ctx); 
	(*f_hash)((const unsigned char *)&t_cost,isz,&ctx);
	(*f_hash)((const unsigned char *)&i,isz,&ctx);
	(*f_end)((void *)digest,&ctx);

	ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
	(*f_hash)((const unsigned char *)digest,DIGEST_SIZE,&ctx);
	(*f_end)((void *)&X[0],&ctx);

	for (i=1;i<m_cost;i++){

		ctx_reinit(&ctx,(unsigned char *)h);
		(*f_hash)((const unsigned char *)&X[i-1],DIGEST_SIZE,&ctx);
		(*f_hash)((const unsigned char *)&t_cost,isz,&ctx);
		(*f_hash)((const unsigned char *)&i,isz,&ctx);
		(*f_end)((void *)digest,&ctx);

		ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
		(*f_hash)((const unsigned char *)digest,DIGEST_SIZE,&ctx);
		(*f_end)((void *)&X[i],&ctx);
	}

	/* obtain H(salt + ipad) and H(salt + opad) */

	PRF_init((unsigned char *)h,(const unsigned char *)salt,saltlen);

	ctx_reinit(&ctx,(unsigned char *)h);
	(*f_hash)((const unsigned char *)in,inlen,&ctx);
	(*f_hash)((const unsigned char *)&X[m_cost-1],DIGEST_SIZE,&ctx);
	(*f_end)((void *)shash,&ctx);

	ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
	(*f_hash)((const unsigned char *)shash,DIGEST_SIZE,&ctx);
	(*f_end)((void *)shash,&ctx);

	/* obtain H(shash + ipad) and H(shash + opad) */

	PRF_init((unsigned char *)h,(const unsigned char *)shash,DIGEST_SIZE);

#if defined(_64BIT)
	uint64_t *dp = (uint64_t *)&X[m_cost-1];
#else
	uint32_t *dp = (uint32_t *)&X[m_cost-1];
#endif

	for (i=0;i<t_cost;i++){

		k = dp[lword] & mask0;

		ctx_reinit(&ctx,(unsigned char *)h);
		(*f_hash)((const unsigned char *)&X[k],DIGEST_SIZE,&ctx);
		(*f_hash)((const unsigned char *)dp,DIGEST_SIZE,&ctx);
		(*f_hash)((const unsigned char *)&i,isz,&ctx);
		(*f_end)((void *)digest,&ctx);

		ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
		(*f_hash)((const unsigned char *)digest,DIGEST_SIZE,&ctx);
		(*f_end)((void *)&V[i & mask1],&ctx);
		
#if defined(_64BIT)
		dp = (uint64_t *)&V[i & mask1];
#else
		dp = (uint32_t *)&V[i & mask1];
#endif
	}
	
	ctx_reinit(&ctx,(unsigned char *)h);
	(*f_hash)((const unsigned char *)in,inlen,&ctx);
	(*f_hash)((const unsigned char *)salt,saltlen,&ctx);
	(*f_hash)((const unsigned char *)dp,DIGEST_SIZE,&ctx);
	(*f_hash)((const unsigned char *)&t_cost,isz,&ctx);
	(*f_end)((void *)shash,&ctx);

	ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
	(*f_hash)((const unsigned char *)shash,DIGEST_SIZE,&ctx);
	(*f_end)((void *)shash,&ctx);
		
	int r = (outlen % DIGEST_SIZE);
	unsigned int l = (unsigned int)(outlen / DIGEST_SIZE);
	l = ((r) ? (l+1) : l);
	
	/* obtain H(shash + ipad) and H(shash + opad) */

	PRF_init((unsigned char *)h,(const unsigned char *)shash,DIGEST_SIZE);

	unsigned char *tp = (unsigned char *)out;

	for (i=0;i<l;i++){

		ctx_reinit(&ctx,(unsigned char *)h);
		(*f_hash)((const unsigned char *)in,inlen,&ctx);
		(*f_hash)((const unsigned char *)dp,DIGEST_SIZE,&ctx);
		
		int j;
		for (j=0;j<_VSIZE;j++)
			(*f_hash)((const unsigned char *)&V[j],DIGEST_SIZE,&ctx);
		(*f_end)((void *)digest,&ctx);

		ctx_reinit(&ctx,(unsigned char *)&h[DIGEST_SIZE]);
		(*f_hash)((const unsigned char *)digest,DIGEST_SIZE,&ctx);

		if ((i == (l-1)) && (r)){
			(*f_end)((void *)digest,&ctx);
			memcpy(tp,digest,r);
		}else{
			(*f_end)((void *)tp,&ctx);
#if defined(_64BIT)
			dp = (uint64_t *)tp;
#else
			dp = (uint32_t *)tp;
#endif
			if (i < (l-1))
				tp += DIGEST_SIZE;
		}	
	}
}

void PRF_init
(
	unsigned char *h,		/* output buffer */
	const unsigned char *key,	/* secret key	 */
	unsigned long int klen		/* key length	 */
)
{
	hash_ctx	ctx;

#if defined(_64BIT)
	/* align temp buffer to 64-bit word length */

	unsigned char	k[BLOCK_SIZE]
	__attribute__((__aligned__(__alignof__(uint64_t))));
#else
	/* align temp buffer to 32-bit word length */

	unsigned char	k[BLOCK_SIZE]
	__attribute__((__aligned__(__alignof__(uint32_t))));
#endif
	unsigned char *s = (unsigned char *)key;
	int i;

	if (klen > BLOCK_SIZE){

		(*f_begin)(&ctx);
		(*f_hash)(key,klen,&ctx);
		(*f_end)((void *)k,&ctx);

		s = k;
		klen = DIGEST_SIZE;
	}
	
	/*** inner key ***/

	for (i=0;i<klen;i++)
		k[i] = s[i]^0x36;
	for (i=klen;i<BLOCK_SIZE;i++)
		k[i] = 0x36;

	(*f_begin)(&ctx);
	(*f_hash)((const unsigned char *)k,BLOCK_SIZE,&ctx);
	(*f_end)((void *)&h[0],&ctx);

	/*** outer key ***/

	/* 
	   note that k[i] = key[i] ^ 0x36 and
	   0x36 ^ 0x5c = 0x6a 			
	*/

	for (i=0;i<BLOCK_SIZE;i++)
		k[i] ^= 0x6a;

	(*f_begin)(&ctx);
	(*f_hash)((const unsigned char *)k,BLOCK_SIZE,&ctx);
	(*f_end)((void *)&h[DIGEST_SIZE],&ctx);

	/*** clear buffers ***/

	memset(k,0,BLOCK_SIZE);
	memset(&ctx,0,sizeof(ctx));
}

void ctx_reinit(hash_ctx *ctx,unsigned char *hkey)
{
	/* initialise context */

	ctx->count[0] = ctx->count[1] = 0;
	memcpy((unsigned char *)ctx->hash,hkey,DIGEST_SIZE);
}

#if defined(__cplusplus)
}
#endif
