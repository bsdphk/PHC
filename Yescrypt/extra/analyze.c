#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static void analyze(unsigned char *Vc, size_t n)
{
	static uint64_t Vmap32[2][0x100000000 / 64];
	static uint64_t Vmap16[4][2][0x10000 / 64];
	static int called;
	uint32_t *Vi = (uint32_t *)Vc;
	size_t i;
	size_t counts[0x100], min, max, diff32[2], diff16[4][2], sum;

	fprintf(stderr, "n = %llu\n", (unsigned long long)n);

	memset(counts, 0, sizeof(counts));
	for (i = 0; i < n; i++)
		counts[Vc[i]]++;
	min = ~0UL; max = 0;
	for (i = 0; i < 0x100; i++) {
		if (min > counts[i])
			min = counts[i];
		if (max < counts[i])
			max = counts[i];
	}
	fprintf(stderr, "min = %llu max = %llu"
	    " (min+max)/2 = %.1f (expected %.1f)\n",
	    (unsigned long long)min, (unsigned long long)max,
	    (double)(min + max) / 2.0, (double)n / 0x100);

	n /= sizeof(uint32_t);
	/* Assume the statics are zero on first call */
	if (called) {
		memset(Vmap32, 0, sizeof(Vmap32));
		memset(Vmap16, 0, sizeof(Vmap16));
	}
	called = 1;
	memset(diff32, 0, sizeof(diff32));
	memset(diff16, 0, sizeof(diff16));
	for (i = 0; i < n; i++) {
		uint32_t x = Vi[i];
		uint32_t lo = x & 0xffff;
		uint32_t hi = x >> 16;
		uint64_t * v = &Vmap32[i & 1][x / 64];
		if (!(*v & ((uint64_t)1 << (x % 64))))
			diff32[i & 1]++;
		*v |= (uint64_t)1 << (x % 64);
		v = &Vmap16[i & 3][0][lo / 64];
		if (!(*v & ((uint64_t)1 << (lo % 64))))
			diff16[i & 3][0]++;
		*v |= (uint64_t)1 << (lo % 64);
		v = &Vmap16[i & 3][1][hi / 64];
		if (!(*v & ((uint64_t)1 << (hi % 64))))
			diff16[i & 3][1]++;
		*v |= (uint64_t)1 << (hi % 64);
	}
	sum = 0;
	for (i = 0; i < 4; i++)
		sum += diff16[i][0] + diff16[i][1];
	fprintf(stderr,
	    "diff32 = %llu %llu"
	    " (expected %.1f)\n"
	    "diff16 = %llu %llu %llu %llu %llu %llu %llu %llu avg = %.1f"
	    " (expected %.1f)\n",
	    (unsigned long long)diff32[0], (unsigned long long)diff32[1],
	    (1ULL<<32) * (1.0 - pow(((1ULL<<32) - 1.0) / (1ULL<<32), n / 2.0)),
	    (unsigned long long)diff16[0][0], (unsigned long long)diff16[0][1],
	    (unsigned long long)diff16[1][0], (unsigned long long)diff16[1][1],
	    (unsigned long long)diff16[2][0], (unsigned long long)diff16[2][1],
	    (unsigned long long)diff16[3][0], (unsigned long long)diff16[3][1],
	    sum / 8.0,
	    0x10000 * (1.0 - pow((0x10000 - 1.0) / 0x10000, n / 4.0)));
}

int main(void)
{
	static unsigned char V[0x10000000];
	size_t n;

	n = fread(V, 1, sizeof(V), stdin);
	if (ferror(stdin)) {
		perror("fread");
		return 1;
	}

	analyze(V, n);

	return 0;
}
