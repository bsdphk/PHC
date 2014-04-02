#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/md5.h>

enum {
	N = 0x100000,
	B = 0x0b0b0b0b
};

static uint32_t t_cost;
static double at_cost1, at_cost2;
static uint32_t hits[N], nhits, mhits;

static uint64_t V[N];

static uint64_t H(uint64_t x)
{
	MD5_CTX ctx;
	union {
		uint64_t i;
		unsigned char c[MD5_DIGEST_LENGTH];
	} y;

	t_cost++;

	MD5_Init(&ctx);
	MD5_Update(&ctx, &x, sizeof(x));
	MD5_Final(y.c, &ctx);

	return y.i;
}

static void count_hits(void)
{
	uint32_t i;

	nhits = mhits = 0;
	for (i = 0; i < N; i++) {
		if (hits[i])
			nhits++;
		if (hits[i] > mhits)
			mhits = hits[i];
	}
}

static void print_hits(const char *title)
{
	printf("%s: nhits=%u (%.2f%%) mhits=%u\n",
	    title, nhits, 100.0 * nhits / N, mhits);
}

static void print_costs(uint64_t Bout)
{
	printf(
	    "B' = %16llx\n"
	    "t_cost = %u\n"
	    "at_cost1 = %.0f "
	    "at_cost2 = %.0f "
	    "at_cost = %.0f\n"
	    "at_cost1/t = %.0f "
	    "at_cost2/t = %.0f "
	    "at_cost/t = %.0f\n",
	    Bout,
	    t_cost, at_cost1, at_cost2, at_cost1 + at_cost2,
	    at_cost1 / t_cost, at_cost2 / t_cost, (at_cost1 + at_cost2) / t_cost);
}

static void smix_classic(void)
{
	uint64_t X = B;
	uint32_t i, j;

	puts("classic");

	t_cost = 0;

	for (i = 0; i < N; i++) {
		hits[i] = 0;

		V[i] = X;
		X = H(X);
	}

	at_cost1 = N * sqrt(N); /* sqrt(N) parallel cores attack with extreme recursion */
	at_cost2 = 0;

	for (i = 0; i < N; i++) {
		j = X % N;
		X = H(X ^ V[j]);

		hits[j]++;
		at_cost2 += N; /* 1 time * N area */
	}

	count_hits();

	at_cost2 /= 2; /* extreme TMTO */

	print_costs(X);
	print_hits("total");
	puts("");
}

static void smix_loop1_pow2(uint32_t N2div)
{
	uint64_t X = B;
	uint32_t i, j, n, N2;

	printf("loop1_pow2(N2 = N/%u)\n", N2div);

	t_cost = 0;
	at_cost1 = at_cost2 = 0;

	n = 1;
	for (i = 0; i < N; i++) {
		V[i] = X;

		hits[i] = 0;
		if (i > 1) {
			if ((i & (i - 1)) == 0)
				n <<= 1;
			j = (X & (n - 1)) + (i - n);
			if (j >= i)
				fprintf(stderr, "Bad j = %08x\n", j);
			hits[j]++;

			X ^= V[j];
		}

		X = H(X);

		at_cost1 += n; /* 1 time * n area */
	}

	count_hits();
	print_hits("loop1");

	N2 = N / N2div;
	for (i = 0; i < N2; i++) {
		j = X % N;
		X = H(X ^ V[j]);

		hits[j]++;
		at_cost2 += N; /* 1 time * N area */
	}

	count_hits();

	at_cost1 /= 2; /* extreme TMTO, probably impossible */
	at_cost2 /= 2; /* extreme TMTO, probably impossible */

	print_costs(X);
	print_hits("total");
	puts("");
}

static uint32_t
wrap(uint64_t x, uint32_t n)
{
	uint64_t a = (x + n) & (n - 1);
	uint64_t b = x & n;
	uint64_t c = (x << 1) & n;
	return ((a << 1) + b + c) >> 2;
}

static void smix_loop1_wrap(uint32_t N2div)
{
	uint64_t X = B;
	uint32_t i, j, N2;

	printf("loop1_wrap(N2 = N/%u)\n", N2div);

	t_cost = 0;
	at_cost1 = at_cost2 = 0;

	for (i = 0; i < N; i++) {
		V[i] = X;

		hits[i] = 0;
		if (i > 1) {
			j = wrap(X, i);
			if (j >= i)
				fprintf(stderr, "Bad j = %08x\n", j);
			hits[j]++;

			X ^= V[j];
		}

		X = H(X);

		at_cost1 += i; /* 1 time * i area (although not all j's in [0,i-1] are possible for a given i) */
	}

	count_hits();
	print_hits("loop1");

	N2 = N / N2div;
	for (i = 0; i < N2; i++) {
		j = X % N;
		X = H(X ^ V[j]);

		hits[j]++;
		at_cost2 += N; /* 1 time * N area */
	}

	count_hits();

	at_cost1 /= 2; /* extreme TMTO, probably impossible */
	at_cost2 /= 2; /* extreme TMTO, probably impossible */

	print_costs(X);
	print_hits("total");
	puts("");
}

static void smix_loop1_mod(uint32_t N2div)
{
	uint64_t X = B;
	uint32_t i, j, N2;

	printf("loop1_mod(N2 = N/%u)\n", N2div);

	t_cost = 0;
	at_cost1 = at_cost2 = 0;

	for (i = 0; i < N; i++) {
		V[i] = X;

		hits[i] = 0;
		if (i > 1) {
			j = X % i; /* drawbacks: depends on chosen size of X (beyond bits in N-1), somewhat slow, not constant time, slightly non-uniform when size of X is not a lot larger than log2(N) */
			if (j >= i)
				fprintf(stderr, "Bad j = %08x\n", j);
			hits[j]++;

			X ^= V[j];
		}

		X = H(X);

		at_cost1 += i; /* 1 time * i area */
	}

	count_hits();
	print_hits("loop1");

	N2 = N / N2div;
	for (i = 0; i < N2; i++) {
		j = X % N;
		X = H(X ^ V[j]);

		hits[j]++;
		at_cost2 += N; /* 1 time * N area */
	}

	count_hits();

	at_cost1 /= 2; /* extreme TMTO, probably impossible */
	at_cost2 /= 2; /* extreme TMTO, probably impossible */

	print_costs(X);
	print_hits("total");
	puts("");
}

int main(void)
{
	smix_classic();
	smix_loop1_pow2(1);
	smix_loop1_pow2(3);
	smix_loop1_wrap(1);
	smix_loop1_wrap(2);
	smix_loop1_mod(1);
	smix_loop1_mod(2);
	return 0;
}
