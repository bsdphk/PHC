#ifndef PHS_H
#define PHS_H

#include "ocrypt.h"

int PHS(void *, size_t, const void *, size_t, const void *, size_t,
	unsigned int, unsigned int);


int PHS(void *out, size_t outlen, const void *in, size_t inlen,
	const void *salt, size_t saltlen, unsigned int t_cost,
	unsigned int m_cost) {

  /* PHS doesn't take a secret key so send a null, zero-len key to ocrypt */
  return ocrypt((uint8_t *)out, outlen, (uint8_t *)in, inlen,
		(uint8_t *)salt, saltlen, NULL, 0,
		t_cost, m_cost);
}


#endif
