#include <stdlib.h>
#include <string.h>

static void xor_each(unsigned char * A, const unsigned char * B, const unsigned int sz) {

	const unsigned char * B_end = B + sz;

	while (B != B_end)
		*A++ ^= *B++;
}

static unsigned char * dflt_permutation(const unsigned int n, unsigned char * res,
 const unsigned char * x, const unsigned int w,
 const unsigned char * f_data, const unsigned int f_data_size) {

	unsigned int i;

	for (i = 0; i < w; ++i) {

		/* Use a different algebraic order so that our xors don't cancel. */
		res[i] = x[i] + f_data[(n + i) % f_data_size];
	}

	return res;
}

static unsigned char * turtle_(unsigned char * res,
 const unsigned char * X, const unsigned int sz,
 const unsigned int w, unsigned int * n,
 unsigned char * (*f)
  (const unsigned int, unsigned char *, const unsigned char *, const unsigned int,
                                           const unsigned char *, const unsigned int),
 const unsigned char * f_data, const unsigned int f_data_size) {

	unsigned char L[sz >> 1];
	unsigned char R[sz - sizeof(L)];

	unsigned char tmp[sizeof(R)];

	if (sz == w) {

		return f((*n)++, res, X, w, f_data, f_data_size);
	}

	memcpy(L, X            , sizeof(L));
	memcpy(R, X + sizeof(L), sizeof(R));

	xor_each(R, turtle_(tmp, L, sizeof(L), w, n, f, f_data, f_data_size), sizeof(R));
	xor_each(L, turtle_(tmp, R, sizeof(R), w, n, f, f_data, f_data_size), sizeof(L));

	xor_each(R, turtle_(tmp, L, sizeof(L), w, n, f, f_data, f_data_size), sizeof(R));
	xor_each(L, turtle_(tmp, R, sizeof(R), w, n, f, f_data, f_data_size), sizeof(L));

	memcpy(res            , L, sizeof(L));
	memcpy(res + sizeof(L), R, sizeof(R));

	return res;
}

unsigned char * turtle(unsigned char * res,
 const unsigned char * X, const unsigned int sz, const unsigned int w,
 unsigned char * (*f)(const unsigned int, unsigned char *, const unsigned char *,
                        const unsigned int, const unsigned char *, const unsigned int),
 unsigned char * f_data, const unsigned int f_data_size) {

	unsigned int n = 0;

	return turtle_(res, X, sz, w, &n, f ? f : dflt_permutation, f_data, f_data_size);
}

unsigned char * turtle_inplace(
 unsigned char * X, const unsigned int sz, const unsigned int w,
 unsigned char * (*f)(const unsigned int, unsigned char *, const unsigned char *,
                        const unsigned int, const unsigned char *, const unsigned int),
 unsigned char * f_data, const unsigned int f_data_size) {

	unsigned char tmp[sz];

   turtle(tmp, X, sz, w, f, f_data, f_data_size);

	memcpy(X, tmp, sz);

	return X;
}
