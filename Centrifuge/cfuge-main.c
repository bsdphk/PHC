/*
	Centrifuge, sample main program to test performance and generate test vectors
	2014 (c) Rafael Alvarez
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "cfuge.h"

int main(int argc, char * argv[]) {
	uint8_t pass[32];
	uint8_t salt[32];
	uint8_t out[4096];
	int perf = 0;
	int tvec = 0;
	
	if(argc<2) {
		printf("Nothing to do. Try perf or tvec\n");
		return -1;
	}

	for(int i=1; i<argc; i++) {
		int match = 0;
		
		if(!strcmp(argv[i],"perf")) {
			match = 1;
			perf = 1;
		}

		if(!strcmp(argv[i],"tvec")) {
			match = 1;
			tvec = 1;
		}

	
		if(!match) {
			fprintf(stderr,"ERROR: invalid parameter '%s'\n",argv[i]);
			return -1;
		}
	}

	


	if(perf) {
		memset(pass,0,32);
		memset(salt,0,32);

		printf("\n\n**Performance \n\n");

		for(int i=0; i<21; i++) {
			for(int j=0; j<9; j++) {
				clock_t t = clock();
			    PHS(out,32,pass,32,salt,32,j,i);
			    t = clock() - t;
			    printf("m=%02u,t=%02u,%f sec \n",i,j,((float)t)/CLOCKS_PER_SEC);
		 	}
		}

	}

	if(tvec) {

		memset(pass,0,32);
		memset(salt,0,32);
		
		printf("\n\nTest Vectors (password, salt, output) with t_cost=4 and m_cost=16\n\n");

		for(int i=0; i<32; i++) {
			for(int j=0; j<256; j++) {
				
				PHS(out,32,pass,32,salt,32,4,16);
				for(int k=0; k<32; k++)	printf("%02X",pass[k]);
				printf(",");
				for(int k=0; k<32; k++)	printf("%02X",salt[k]);
				printf(",");
				for(int k=0; k<32; k++)	printf("%02X",out[k]);
				printf("\n");	
				pass[i]++;
			}
		}

		memset(pass,0,32);
		for(int i=0; i<32; i++) {
			for(int j=0; j<256; j++) {
				
				PHS(out,32,pass,32,salt,32,4,16);
				for(int k=0; k<32; k++)	printf("%02X",pass[k]);
				printf(",");
				for(int k=0; k<32; k++)	printf("%02X",salt[k]);
				printf(",");
				for(int k=0; k<32; k++)	printf("%02X",out[k]);
				printf("\n");	
				salt[i]++;
			}
		}

	}

	return 0;

}

