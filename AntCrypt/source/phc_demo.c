#include <inttypes.h>    /* C99 fixed-width integer types w/ output macros */
#include <stdio.h>       /* printf */
#include <stdlib.h>      /* rand, srand */
#include <string.h>      /* memcpy, strncpy, strlen */
#include <time.h>        /* time */

/* PHC definitions, types and prototypes */
#include "phc_debug.h"
#include "phc.h"

/* print hex strings to stdout */
void print_hex(unsigned char *A, int length) {
	int i;
	for(i = 0; i < length; i++) {
		printf("%02x", A[i]);
	}
}

#define NUM_CONST_SALTS (3)

const uint8_t const_salt[NUM_CONST_SALTS][PHS_SALT_SIZE] = { 
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 
	{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
	{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAa, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA } 
};

/* main function for demonstration purpose */
int main(int argc, char *argv[]){
	uint8_t salt[PHS_SALT_SIZE];
	uint8_t in[256];
	uint8_t in_len;
	uint32_t ret;
	uint8_t salt_len = PHS_SALT_SIZE;
	uint32_t t_cost;
	uint32_t m_cost;
	uint32_t outlen;
	uint8_t *out;

	/* check if we have one paramter to demonstrate the function */
	if (argc != 5) {
		printf("PHC submission demo\n");
		printf("Usage: phc <t_cost> <m_cost> <outlen> <pwd>\n");
		printf("Demo notes: outlen is the size in BYTE\n");
		return 1;
	}

	/* parse command line parameters */
	if (sscanf(argv[1], "%"SCNu32, &t_cost) != 1) {
		printf("Invalid parameter t_cost!\n");
		return 1;
	}
	if (sscanf(argv[2], "%"SCNu32, &m_cost) != 1) {
		printf("Invalid parameter m_cost!\n");
		return 1;
	}
	if (sscanf(argv[3], "%"SCNu32, &outlen) != 1) {
		printf("Invalid parameter outlen!\n");
		return 1;
	}


	/* copy password and store length*/
	strncpy((char *)in, argv[4], 255);
	in_len = strlen((const char *)in);

	printf("Parameters: t_cost = %" PRIu32 ", m_cost = %" PRIu32"\n", t_cost, m_cost);
	printf("Input     : %s\n", in);

	for (uint8_t i = 0; i < NUM_CONST_SALTS; i++) {
		/* copy salt */
		/* TODO: read salt from command line for better demonstration */
		memcpy(salt, const_salt[i], PHS_SALT_SIZE); 

		/* allocate memory for output */
		out = (uint8_t *) malloc(outlen * sizeof(uint8_t));

		/* call the PHS */
		ret = PHS(out, outlen, in, in_len, salt, salt_len, t_cost, m_cost);
		if ( ret != 0 ) {
			printf("Error: PHS() returned with error code %i\n", ret);
			return 1;
		}
		Dprintf("Info:  PHS() returned with error code 0\n");
		/* $t_cost$m_cost$salt$hash */
		printf("Output    : $");
		print_hex(salt, PHS_SALT_SIZE);
		printf("$%" PRIu32 ":%" PRIu32"$", t_cost, m_cost);
		print_hex(out, outlen);
		printf("\n");
	}
	/* free memory from output buffer */
	free(out);

	/* done */
	return 0;
}
