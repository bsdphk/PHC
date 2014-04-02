#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "lanarea.h"

int main (void) {
	int x, y;
	uint8_t pass[32], salt[32], out[32];
	for (x = 0; x < 256; x++) {
		// set bytes to value each round
		for (y = 0; y < 32; y++) {
			pass[y] = x;
			salt[y] = x;
		}

		// run the function
		lanarea (out, 32, pass, 32, salt, 32, 1, 1);

		// print the result
		printf ("0x%02X:\t", x);
		for (y = 0; y < 32; y++) {
			printf ("%02hhx", out[y]);
		}
		printf ("\n");
	}

	return 0;
}
