/*
	Centrifuge, a password hashing algorithm
	2014 (c) Rafael Alvarez
*/
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cfuge.h"



int PHS(void *out, size_t outlen, const void *in, size_t inlen, 
	const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t m,t;

	if((m_cost > 63)||(t_cost > 63)) return -1;
	
	m = (uint64_t) 1<<(m_cost);
	t = (uint64_t) 1<<(t_cost);
	return cfuge(in,inlen,salt,saltlen,out,outlen,m,t);
}


// 512 bit hash
void H(const uint8_t *in, size_t len, uint8_t *out) {
	SHA512(in,len,out);	
}

// encryption function (CFB mode)
static AES_KEY 		c_key;
static uint8_t 		c_iv[16];
static int 			c_num;

void initC(uint8_t *key, uint8_t *iv) {
	AES_set_encrypt_key((unsigned char *)key,256,&c_key);
	memset(&c_num,0,sizeof(c_num));
	memcpy(c_iv,iv,AES_BLOCK_SIZE);
}

void C(void *in, void *out, size_t len) {
	AES_cfb128_encrypt((uint8_t *)in,(uint8_t *)out,len,&c_key,c_iv,&c_num,AES_ENCRYPT);
}


int cfuge(	const uint8_t *password, uint32_t passlen,	// password and length
			const uint8_t *salt, uint32_t saltlen,  	// salt and length
			uint8_t *out, uint32_t outlen,				// output buffer and length
			const uint64_t p_mem, 						// memory parameter 
			const uint64_t p_time 						// time parameter 
			)		
{
	uint8_t *M; 		// memory table
	uint8_t iv[16];		// initialization value (128 bit) for C
	uint8_t key[32];	// key (256 bit) for C
	uint8_t S[256];		// s-box
	uint8_t *Seq;		// sequence to evolve s-box


	// allocate memory
	M = malloc(p_mem * outlen);
	if(!M) return -1;
	Seq = calloc(p_time,1);
	if(!Seq) return -1;
	
	//printf("%llu ",p_mem * outlen / (1024*1024));

	// seeding
	{
		uint8_t seedin[128],seedout[64];

		H(password,passlen,seedin);
		H(salt,saltlen,seedin+64);
		H(seedin,128,seedout);

		for(int i=0; i<outlen; i++) 
			out[i] = seedout[i%16];
		
		memcpy(iv,seedout+16,16);
		memcpy(key,seedout+32,32);

		initC(key,iv);
	}

	// s-box initialization
	{
		uint8_t buf[256];
		uint8_t m,l,t;

		memset(buf,0,256);
		C(buf,buf,256);

		for(int i=0; i<256; i++) {
			S[i] = (uint8_t)i;
		}

		for(int i=0; i<256; i++) {
			m = (uint8_t)i;
			l = buf[i];
			t = S[m];
			S[m] = S[l];
			S[l] = t;
		}

	}

	// build table
	{
		
		uint8_t m,l,t;		// indexes to S
		uint64_t offs = 0;	// offset into M

		for(uint64_t i=0; i<p_mem; i++) {
			
			// generate sequence
			C(Seq,Seq,p_time);
			
			// modify S
			for(uint64_t j=0; j<p_time; j++) {	
				m = (uint8_t) j % 256;
				l = Seq[j];
				t = S[m];
				S[m] = S[l];
				S[l] = t;
			}

			// process output
			for(uint32_t j=0; j<outlen; j++) 
				out[j] = S[out[j]];

			// encrypt output
			C(out,out,outlen);
			
			// copy to M
			memcpy(M+offs,out,outlen);
			offs += outlen;

		}

	}

	// output
	{		
		uint64_t index = 0;	// index into M
		uint8_t *ptr;		// pointer to start of current M row
		uint8_t m,l,t;		// indexes to S

		
		// process entry
		for(uint64_t i=0; i<p_mem; i++) {

			// generate sequence
			C(Seq,Seq,p_time);

			// modify S
			for(uint64_t j=0; j<p_time; j++) {	
				m = (uint8_t) j % 256;
				l = Seq[j];
				t = S[m];
				S[m] = S[l];
				S[l] = t;
			}

			// generate next index
			C(&index,&index,8);

			// address to M
			ptr = M + (index % p_mem) * outlen;

			// process and encrypt output
			for(uint32_t j=0; j<outlen; j++) {
				out[j] = (uint8_t)(S[out[j]] + ptr[j]);
			}
			C(out,out,outlen);

		}
	}


	// free memory		
	if(M) free(M);
	if(Seq) free(Seq);
	return 0;
}

