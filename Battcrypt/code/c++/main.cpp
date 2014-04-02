// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#include <stdio.h>
#include "battcrypt.h"

void printHash(uint64_t *hash)
{
	printf(
		"%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n"
		"%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n",
		WRITE_BIG_ENDIAN_64(hash[0]),
		WRITE_BIG_ENDIAN_64(hash[1]),
		WRITE_BIG_ENDIAN_64(hash[2]),
		WRITE_BIG_ENDIAN_64(hash[3]),
		WRITE_BIG_ENDIAN_64(hash[4]),
		WRITE_BIG_ENDIAN_64(hash[5]),
		WRITE_BIG_ENDIAN_64(hash[6]),
		WRITE_BIG_ENDIAN_64(hash[7]));
}

void benchmark(unsigned int t_cost, unsigned int m_cost)
{
	uint64_t out[8];
	TIMER_TYPE s, e;

	TIMER_FUNC(s);
	PHS(out, sizeof(out), "password", 8, "salt", 4, t_cost, m_cost);
	TIMER_FUNC(e);
	printf("battcrypt t:% 2u, m:% 2u: %0.4f ms\n", t_cost, m_cost, 1000.0 * TIMER_DIFF(s, e));
}

int main()
{
	uint64_t out[8];

	PHS(out, sizeof(out), "password", 8, "salt", 4, 0, 0);
	printHash(out);
	printf("?==?\ne22441865a5405c2bbe84a4d6e025133595042886125989fafcf409493638d66\n0803f13cc0fff9e902b3a017cb5b7bceb52ac404be77828dac531f01a25d17da\n\n");

	benchmark(1, 3);
	benchmark(1, 4);
	benchmark(1, 5);
	benchmark(1, 6);
	benchmark(1, 7);
	benchmark(1, 8);
	benchmark(1, 9);
	benchmark(1,10);
	benchmark(1,11);
	benchmark(1,12);
	benchmark(1,13);
	getchar();
	return 0;
}
