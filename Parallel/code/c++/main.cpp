// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#include <stdio.h>
#include "parallel.h"

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

void benchmark(unsigned int t_cost)
{
	uint64_t out[8];
	TIMER_TYPE s, e;

	TIMER_FUNC(s);
	PHS(out, sizeof(out), "password", 8, "salt", 4, t_cost, 0);
	TIMER_FUNC(e);
	printf("parallel t:% 2u: %0.4f ms\n", t_cost, 1000.0 * TIMER_DIFF(s, e));
}

int main()
{
	uint64_t out[8];

	PHS(out, sizeof(out), "password", 8, "salt", 4, 0, 0);
	printHash(out);
	printf("?==?\nb55e191a1a9d770a028b36a36c1aee8beb5349170effcf1ceec28dcd06bab114\nb485cffeca1271401532320a09f83345b6f9dcc6bb3a6caab0afcea15081e44c\n\n");

	benchmark( 0);
	benchmark( 1);
	benchmark( 2);
	benchmark( 3);
	benchmark( 4);
	benchmark( 5);
	benchmark( 6);
	benchmark( 7);
	benchmark( 8);
	benchmark( 9);
	benchmark(10);
	return 0;
}
