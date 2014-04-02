/*
 * Omega Crypt (ocrypt)
 * Brandon Enright <bmenrigh@brandonenright.net>
 * http://www.brandonenright.net/ocrypt/
 *
 * 2014-03-31
 *
 * Placed in the public domain.
 *
 * Submitted to the Password Hashing Competition
 * https://password-hashing.net/index.html
 */


#ifndef OCRYPT_H
#define OCRYPT_H

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "chacha-wrapper.h"
#include "cubehash.h"

int ocrypt(uint8_t *, size_t, uint8_t *, size_t,
	   uint8_t *, size_t, uint8_t *, size_t,
	   unsigned int, unsigned int);


#define OCRYPT_PARAMS_SIZE ((256 * 3) + 3)

#define OCRYPT_BASE_TCOST 17
#define OCRYPT_BASE_MCOST 17
#define OCRYPT_MAX_TCOST  14 /* user input, actually 17 + 14 = 31 */
#define OCRYPT_MAX_MCOST  14 /* user input, actually 17 + 14 = 31 */

/* Omega Crypt return values */
#define OCRYPT_SUCCESS  0
#define OCRYPT_E_OLEN   1
#define OCRYPT_E_PLEN   2
#define OCRYPT_E_SLEN   3
#define OCRYPT_E_KLEN   4
#define OCRYPT_E_MEM    5
#define OCRYPT_E_TCOST  6
#define OCRYPT_E_MCOST  7

#endif
