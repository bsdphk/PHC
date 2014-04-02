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

/* main function for demonstration purpose */
int main(int argc, char *argv[]){
	uint8_t salt[PHS_SALT_SIZE];
	uint8_t pw[2];
	uint32_t ret;
	uint8_t out[64];

	/* initialize the password and salt memory */
	memset(salt, 0x00, PHS_SALT_SIZE);
	memset(pw, 0x00, 2);
	
	/* generate test vectors */
	for (uint8_t i = 0; i < 256; i++) {                            /* "pw" */
		printf("----- Password = %02X -----\n", i);
		pw[0] = i;

		for (uint8_t j = 0; j < 256; j++) {                        /* "salt" */
			salt[0] = j;

			for (uint8_t mcost = 0; mcost < 14; mcost++) {         /* m_cost */
				for (uint8_t tcost = 1; tcost < 20-mcost; tcost++) {     /* t_cost */

					/* call PHS */
					ret = PHS(out, 64, pw, 1, salt, PHS_SALT_SIZE, tcost, mcost);

					if (ret != 0) {
						printf("Error at run: pass = %d, seed = %d, m = %d, t = %d!\n", i, j, mcost, tcost);
					}
					else {
						/* $t_cost$m_cost$salt$hash */
						printf("Parameters: t_cost = %02" PRIu8 ", m_cost = %02" PRIu8 ", pw = %02X, output = $", tcost, mcost, i);
						print_hex(salt, PHS_SALT_SIZE);
						printf("$%02d:%02d$", tcost, mcost);
						print_hex(out, 64);
						printf("\n");
					}
				}
			}
		}
	}

	/* done */
	return 0;
}
