#include "phs.h"

#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT_SIZE 256

int main(int argc, char ** argv) {

	int rc;

	unsigned int i, t_cost, m_cost, output_size;

	unsigned char res[MAX_OUTPUT_SIZE];

	if (argc < 6) {

		fprintf(stderr,
		 "\n\nUsage: %s <num output bytes> <t_cost> <m_cost> <password> <salt>\n\n", argv[0]);

		return 1;
	}

	output_size = atoi(argv[1]);

	if (output_size > MAX_OUTPUT_SIZE) {

		fprintf(stderr, "\n\nMax output size too large.\n\n");
		return 1;
	}

	t_cost = atoi(argv[2]);
	m_cost = atoi(argv[3]);

	rc =
	PHS(res, output_size,
	 (const unsigned char *) argv[4], strlen(argv[4]) + 1,
	 (const unsigned char *) argv[5], strlen(argv[5]) + 1,
	 t_cost, m_cost);

	if (rc != 0) {

		fprintf(stderr, "There was an error.\n");
		return 1;
	}

	for (i = 0; i < output_size; ++i) {

		printf("%02X", res[i]);
	}

	printf("\n");

	return 0;
}
