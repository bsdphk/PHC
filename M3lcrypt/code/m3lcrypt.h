/********************************************************************
 *
 *      FILE       :m3l_crypt.h
 *
 *      DATE       :18/03/14
 *      VERSION    :1.0
 *
 *      CONTENTS   :The M3l_crypt PBKDF reference implementation
 *      REFERENCES :Makwakwa, I., "The M3l_crypt_H PBKDF",
 *                  PHC Competition Submission, March 2014
 *
\********************************************************************/


/* M3L_CRYPT_H */

#ifndef _M3L_CRYPT_H 
#define _M3L_CRYPT_H

#include <sys/types.h>

#if defined(__cplusplus)
extern "C"
{
#endif

/* default hash function */

#ifndef _HF
#define _HF 0
#endif

#ifndef _VSIZE
#define _VSIZE 16
#endif

/* hash function definition */

#define VOID_RETURN void

#include "Sha2.h"

/* stay a while */

#if _HF == 0
#define hash_ctx sha256_ctx
#endif
#if _HF == 1
#define hash_ctx sha512_ctx
#endif

typedef struct hfn {
	void (*begin)(hash_ctx *);
	void (*hash)(const unsigned char *,unsigned long int,hash_ctx *);
	void (*end)(void *,hash_ctx *);
} hash_fn;

typedef struct hsz{
	int DIGEST_SIZE;
	int BLOCK_SIZE;
} hash_sz;

#if _HF == 0
hash_fn hf = {sha256_begin,sha256_hash,sha256_end};
#endif
#if _HF == 1
hash_fn hf = {sha512_begin,sha512_hash,sha512_end};
#endif

hash_sz hsize[2] = { {32,64}, {64,128} };

#define f_begin hf.begin
#define f_hash hf.hash
#define f_end hf.end

#define DIGEST_SIZE hsize[_HF].DIGEST_SIZE
#define BLOCK_SIZE hsize[_HF].BLOCK_SIZE

/* functional prototypes */
void PRF_init(unsigned char *,const unsigned char *,unsigned long int);
void ctx_reinit(hash_ctx *,unsigned char *);
int PHS(void *,size_t,const void *,size_t,void *,size_t,unsigned int,unsigned int);

#endif 

#if defined(__cplusplus)
}
#endif

/* M3L_CRYPT_H */

