#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

int main(){

	size_t saltlen = 16;
	size_t outlen  = 32;
	unsigned int t_cost = (unsigned int)pow(2,14);
	unsigned int m_cost = (unsigned int)pow(2,15);
	int i;

	char *passwd="password";
	uint8_t res[outlen] 
	__attribute__((__aligned__(__alignof__(uint32_t))));
	
	srand(time(NULL));
	rand();
	uint32_t salt[saltlen >> 2];
	for (i=0;i<(saltlen >> 2);i++)
		salt[i] = rand();

	clock_t start = -clock();

	PHS((void *)res,outlen,(void *)passwd,strlen(passwd),(void *)salt,saltlen,t_cost,m_cost);

	start += clock();
	
	float sec = (float)start/CLOCKS_PER_SEC;
	printf("%.3f secs,%.3f passwords\n",sec,(float)(1/sec));
	
	return 0;
}

