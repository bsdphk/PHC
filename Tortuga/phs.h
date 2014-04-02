#ifndef PHS_H
#define PHS_H

#include <stddef.h>

#define PHS_MAX_SALT_SIZE    256

#define PHS_MAX_INPUT_SIZE 65536

#define PHS_OK                    0
#define PHS_ERROR_INPUT_TOO_LONG  1
#define PHS_ERROR_SALT_TOO_LONG   2
#define PHS_ERROR_INVALID_INPUT   4

#ifdef __cplusplus
extern "C" {
#endif

unsigned int PHS_internal_key_size(const unsigned int m_cost);

int PHS(void *out , size_t outlen ,
  const void *in  , size_t inlen  ,
  const void *salt, size_t saltlen,
 unsigned int t_cost, unsigned int m_cost);

#ifdef __cplusplus
}
#endif

#endif
