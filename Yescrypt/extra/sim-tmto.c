#include <stdint.h>
#include <stdio.h>
#include <openssl/md5.h>

enum {
	N = 0x100,
	B = 0x0b0b0b0b,
	TMTO = 5
};

static uint32_t t_cost;
static uint32_t V[N];

static uint32_t H(uint32_t x)
{
	MD5_CTX ctx;
	union {
		uint32_t i;
		unsigned char c[MD5_DIGEST_LENGTH];
	} y;

	t_cost++;

	MD5_Init(&ctx);
	MD5_Update(&ctx, &x, sizeof(x));
	MD5_Final(y.c, &ctx);

	return y.i;
}

static void smix_classic(void)
{
	uint32_t X = B;
	uint32_t i, j;

	t_cost = 0;

	for (i = 0; i < N; i++) {
		V[i] = X;
		X = H(X);
	}

	for (i = 0; i < N; i++) {
		j = X % N;
		X = H(X ^ V[j]);
	}

	printf(
	    "scrypt classic:\n"
	    "B' = %08x\n"
	    "t_cost = %u\n"
	    "m_cost = %u\n",
	    X, t_cost, N);
}

static void smix_classic_tmto(void)
{
	uint32_t X = B;
	uint32_t i, j;

	t_cost = 0;

	for (i = 0; i < N; i++) {
		if ((i % TMTO) == 0)
			V[i / TMTO] = X;
		X = H(X);
	}

	for (i = 0; i < N; i++) {
		uint32_t Vj;
		j = X % N;
		Vj = V[j / TMTO];
		j %= TMTO;
		while (j--)
			Vj = H(Vj);
		X = H(X ^ Vj);
	}

	printf(
	    "scrypt TMTO = %u:\n"
	    "B' = %08x\n"
	    "t_cost = %u\n"
	    "m_cost = %u\n",
	    TMTO, X, t_cost, 1 + (N - 1) / TMTO);
}

static void smix_ircmaxell(void)
{
	uint32_t X = B;
	uint32_t i, j;

	t_cost = 0;

	for (i = 0; i < N; i++) {
		V[i] = X;
		X = H(X);
	}

	for (i = 0; i < N; i++) {
		j = X % N;
		X = H(V[j] ^= X);
	}

	printf(
	    "scrypt ircmaxell:\n"
	    "B' = %08x\n"
	    "t_cost = %u\n"
	    "m_cost = %u\n",
	    X, t_cost, N);
}

static void smix_ircmaxell_tmto(void)
{
	uint32_t V2[(N - 1) / 2 + 1];
	uint32_t patharea[N*N], *pathend;
	uint32_t *path[N], pathlen[N], pathleni[N];

	uint32_t getVrec(uint32_t i, uint32_t j)
	{
		uint32_t xor = 0;

		while (1) {
			if (~i & 1)
				return xor ^ V2[i / 2];

			uint32_t Y = H(V2[i / 2]);
			uint32_t jj = Y % N;
			uint32_t pl = pathleni[i];
			if (pl == 0) {
				uint32_t X = V[j / TMTO];
				j %= TMTO;
				while (j--)
					X = H(X);
				return xor ^ X ^ Y;
			}
			i = path[j][pl - 1];
			j = jj;
			xor ^= Y;
		}
	}

	uint32_t getV(uint32_t i, uint32_t j)
	{
		if (pathlen[j] != 0)
			return getVrec(path[j][pathlen[j] - 1], j);

		uint32_t X;
		X = V[j / TMTO];
		j %= TMTO;
		while (j--)
			X = H(X);
		return X;
	}

	uint32_t X = B;
	uint32_t i, j;

	t_cost = 0;

	for (i = 0; i < N; i++) {
		if ((i % TMTO) == 0)
			V[i / TMTO] = X;
		X = H(X);
		pathlen[i] = 0; /* obvious path, nothing to record yet */
	}

	for (i = 0; i < N; i++) {
		path[i] = &patharea[i];
		patharea[i] = 0xffffffff;
	}
	pathend = &patharea[i];

	for (i = 0; i < N; i++) {
		j = X % N;
		X ^= getV(i, j);
		if (~i & 1)
			V2[i / 2] = X;
		pathleni[i] = pathlen[j];
		if (path[j][pathlen[j]] != 0xffffffff) {
			uint32_t *p = path[j];
			uint32_t *q = &path[j][pathlen[j]];
			path[j] = pathend;
			while (p < q) {
				*pathend++ = *p;
				*p++ = 0xffffffff;
			}
			pathend++;
		}
		path[j][pathlen[j]++] = i;
		X = H(X);
	}

	printf(
	    "scrypt ircmaxell TMTO1 = %u, TMTO2 = 2:\n"
	    "B' = %08x\n"
	    "t_cost = %u\n"
	    "m_cost = %u elements + %u indices "
	    "(%u alloc + %u ptrs) + %u counters\n",
	    TMTO, X, t_cost,
	    1 + (N - 1) / TMTO + sizeof(V2) / sizeof(V2[0]), N,
	    pathend - patharea, N, N * 2);
}

int main(void)
{
	smix_classic();
	smix_classic_tmto();
	smix_ircmaxell();
	smix_ircmaxell_tmto();
	return 0;
}
