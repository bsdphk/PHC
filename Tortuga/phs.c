#include "phs.h"

#include "tortuga.h"

unsigned int PHS_internal_key_size(const unsigned int m_cost) {

	return tortuga_internal_key_size(m_cost);
}

int PHS(void *out , size_t outlen ,
  const void *in  , size_t inlen  ,
  const void *salt, size_t saltlen,
 unsigned int t_cost, unsigned int m_cost) {

	if (inlen > PHS_MAX_INPUT_SIZE)
		return PHS_ERROR_INPUT_TOO_LONG;

	if (saltlen > PHS_MAX_SALT_SIZE)
		return PHS_ERROR_SALT_TOO_LONG;

	if (in == NULL || salt == NULL)
		return PHS_ERROR_INVALID_INPUT;

	tortuga(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost);

	return PHS_OK;
}
