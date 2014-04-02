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

#include "chacha-wrapper.h"


void o_chacha_init(struct chacha_wrapper_ctx *chawctx, uint8_t (*k)[32],
		   uint8_t (*iv)[8]) {

  /* basic init */
  chacha_set_key(&(chawctx->chactx), 32, (uint8_t *)k);
  chacha_set_iv(&(chawctx->chactx), (uint8_t *)iv);

  /* Grab two output blocks */
  chawctx->bptr = 0;
  o_chacha_block(&(chawctx->chactx), &(chawctx->b1));
  o_chacha_block(&(chawctx->chactx), &(chawctx->b2));

}


void o_chacha_block(struct chacha_ctx *chactx, uint8_t (*o)[64]) {

  uint8_t chain[64];
  memset(chain, 0, 64);

  chacha_crypt(chactx, 64, 8, (uint8_t *)o, (uint8_t *)&chain);
}


void o_chacha_getbytes(struct chacha_wrapper_ctx *chawctx,
		       uint8_t *o, size_t s) {

  /* This function fills integers like they're little-endian */

  int i = s - 1;
  while (i >= 0) {
    /* Get bytes out of saved blocks and as the blocks are used up
     * move on to the next block and refresh the previous
     */
    
    if (chawctx->bptr < 64) {
      o[i] = chawctx->b1[chawctx->bptr];
    }
    else {
      o[i] = chawctx->b2[chawctx->bptr - 64];
    }
    chawctx->bptr = (chawctx->bptr + 1) % 128;

    /* If we just finished a blockd replenish it */
    if (chawctx->bptr == 64) {
      o_chacha_block(&(chawctx->chactx), &(chawctx->b1));
    }
    else if (chawctx->bptr == 0) {
      o_chacha_block(&(chawctx->chactx), &(chawctx->b2));
    }

    i--;
  }

}


void o_print_chacha_block(uint8_t (*b)[64]) {

  int i;
  fprintf(stderr, "-- Block --\n");
  for (i = 0; i < 64; i++) {
    if (i != 0) {
      if (i % 32 == 0) {
	fprintf(stderr, "\n");
      }
      else if (i % 8 == 0) {
	fprintf(stderr, " ");
      }
    }
    fprintf(stderr, "%02x", (*b)[i]);
  }
  fprintf(stderr, "\n-- End --\n");

}
