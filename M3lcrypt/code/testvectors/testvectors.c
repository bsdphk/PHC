/********************************************************************
 *
 *      FILE       :testvectors.c
 *
 *      DATE       :18/03/14
 *      VERSION    :1.0
 *
 *      CONTENTS   :Generates test vectors for the M3l_crypt PBKDF
 *      REFERENCES :Makwakwa, I., "The M3l_crypt_H PBKDF",
 *                  PHC Competition Submission, March 2014
 *
\********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include "testvectors.h"

/* create num arbitrary passwords of length len */

void create_keys(char keys[][129],const char *src,size_t len,int num){
	
	srand(rand()+len);

	/* throw away the first 32-bit word */
	rand();

	int i=0,j,k,l,m=strlen(src);
	
	while (i < num){
		
		for (j=0;j<len;j++){
			k = rand() % m;
			keys[i][j] = src[k];
		}
		for (l=0;l<i;l++){
			if (!strncmp(keys[l],keys[i],len)){
				break;
			}
		}
		if (l == i){
			keys[i][len] = '\0';
			i++;
		}else{
			srand(rand());
		}
	}
}

void hprint(unsigned char *in,int len){
	
	int i;
	static char *hex = "0123456789abcdef";

	for (i=0;i<len;i++){
		printf("%c",hex[(in[i] >> 4) & 0xf]);
		printf("%c",hex[(in[i]	   ) & 0xf]);
	}
	printf("\n");
}

void print_r
(
	unsigned char* res,
	unsigned int outlen,
	char *key,
	unsigned char *salt,
	unsigned int saltlen,
	int set,
	int vector,
	int k
)
{

	printf("%s %i,%s %i\n","set",set,"vector",vector);
	printf("%16s","k: ");
	printf("%i\n",k);
	printf("%16s","key: ");
	printf("%s\n",key);
	printf("%16s","salt: ");
	hprint(salt,saltlen);
	printf("%s","cryptovariable: ");
	hprint(res,outlen);
	printf("\n");
}


int main(){

	int saltlen = 16;
	int outlen  = 32;
	unsigned int t_cost = (unsigned int)pow(2,14);
	unsigned int m_cost = (unsigned int)pow(2,15);

	static const char src1[27] = "abcdefghijklmnopqrstuvwxyz";
	static const char src2[96] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 |\\,<.>/?~#'@;:]}[{=+-_)(*&^%$\"!`";

	int i,k,v,s;
	int plen[4] = {2,8,16,32};
	uint32_t salt[saltlen>>2];
	uint32_t out[outlen >> 2];
	char keys[16][129];
	
	v = 0;
	printf("%s\n","Set 1: PW = {\"password\"}^k");
	printf("--------------------------\n");

	char *tkey = "password";
	memset((unsigned char *)salt,0,saltlen);

	for (i=0;i<256;i++){
		salt[0] = i;
		PHS((void *)out,outlen,(void *)tkey,strlen(tkey),(void *)salt,saltlen,t_cost,m_cost);
		print_r((unsigned char*)out,outlen,tkey,(unsigned char *)salt,saltlen,1,v++,1);
	}

	printf("%s\n","Set 2: PW = {26 Alphabet Letters}^k");
	printf("-----------------------------------\n");

	srand(time(NULL));

	/* throw away the first 32-bit word */
	rand(); 
	for (i=0;i<(saltlen>>2);i++)
		salt[i] = rand();

	v = 0;
	for (k=0;k<4;k++){
		create_keys(keys,src1,plen[k],16);
	
		for (i=0;i<16;i++){
			PHS((void *)out,outlen,(void *)keys[i],plen[k],(void *)salt,saltlen,t_cost,m_cost);
			print_r((unsigned char*)out,outlen,keys[i],(unsigned char *)salt,saltlen,2,v++,plen[k]);
		}
	}

	srand(rand());

	/* throw away the first 32-bit word */
	rand(); 
	for (i=0;i<(saltlen>>2);i++)
		salt[i] = rand();

	v = 0;
	printf("%s\n","Set 3: PW = {95 7-bit ASCII Characters}^k");
	printf("-----------------------------------------\n");

	for (k=0;k<4;k++){
		create_keys(keys,src2,plen[k],16);
	
		for (i=0;i<16;i++){
			PHS((void *)out,outlen,(void *)keys[i],plen[k],(void *)salt,saltlen,t_cost,m_cost);
			print_r((unsigned char*)out,outlen,keys[i],(unsigned char *)salt,saltlen,3,v++,plen[k]);
		}
	}

	return 0;
}

