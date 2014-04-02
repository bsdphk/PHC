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


#ifndef CHACHA_WRAPPER_H
#define CHACHA_WRAPPER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "nettle-chacha/chacha.h"


/* A nice wrapper context */
struct chacha_wrapper_ctx {
  struct chacha_ctx chactx;
  int bptr;
  uint8_t b1[64];
  uint8_t b2[64];
};


void o_chacha_init(struct chacha_wrapper_ctx *, uint8_t (*)[32],
		   uint8_t (*)[8]);
void o_chacha_block(struct chacha_ctx *, uint8_t (*)[64]);
void o_print_chacha_block(uint8_t (*)[64]);
void o_chacha_getbytes(struct chacha_wrapper_ctx *, uint8_t *, size_t);

#endif
