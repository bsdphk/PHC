#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "./libb2/src/blake2.h"

int lanarea (
void *out,              // pointer to large enough dest
size_t outlen,          // must be a multiple of 32
const void *in,         // source password
size_t inlen,           // length of source password
const void *salt,       // cryptographic salt
size_t saltlen,         // length of salt
size_t t_cost,          // abstract amount of time to waste
size_t m_cost           // abstract amount of memory to waste
);

int PHS (void *out, size_t outlen, const void *in, size_t inlen,
		const void *salt, size_t saltlen, unsigned int t_cost,
		unsigned int m_cost);
