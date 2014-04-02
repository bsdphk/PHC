/* chacha-init.c
 *
 * Initialization functions for the ChaCha stream cipher.
 * Based on the Salsa20 implementation in Nettle.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Joachim Strömbergon
 * Copyright (C) 2012 Simon Josefsson, Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

/* Based on:
   ChaCha specification (doc id: 4027b5256e17b9796842e6d0f68b0b5e) and reference 
   implementation dated 2008.01.20
   D. J. Bernstein
   Public domain.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "chacha.h"

#include "macros.h"

void
chacha_set_key(struct chacha_ctx *ctx,
		size_t length, const uint8_t *key)
{
  static const uint32_t sigma[4] = {
    /* "expand 32-byte k" */
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
  };
  static const uint32_t tau[4] = {
    /* "expand 16-byte k" */
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574
  };
  const uint32_t *constants;
  
  assert (length == CHACHA_MIN_KEY_SIZE || length == CHACHA_MAX_KEY_SIZE);

  ctx->state[4] = LE_READ_UINT32(key + 0);
  ctx->state[5] = LE_READ_UINT32(key + 4);
  ctx->state[6] = LE_READ_UINT32(key + 8);
  ctx->state[7] = LE_READ_UINT32(key + 12);
  if (length == CHACHA_MAX_KEY_SIZE) { /* recommended */
    ctx->state[8]  = LE_READ_UINT32(key + 16);
    ctx->state[9]  = LE_READ_UINT32(key + 20);
    ctx->state[10] = LE_READ_UINT32(key + 24);
    ctx->state[11] = LE_READ_UINT32(key + 28);
    constants = sigma;
  } else { /* kbits == 128 */
    ctx->state[8]  = ctx->state[4];
    ctx->state[9]  = ctx->state[5];
    ctx->state[10] = ctx->state[6];
    ctx->state[11] = ctx->state[7];
    constants = tau;
  }
  ctx->state[0] = constants[0];
  ctx->state[1] = constants[1];
  ctx->state[2] = constants[2];
  ctx->state[3] = constants[3];
}

void
chacha_set_iv(struct chacha_ctx *ctx, const uint8_t *iv)
{
  ctx->state[12] = 0;
  ctx->state[13] = 0;
  ctx->state[14] = LE_READ_UINT32(iv + 0);
  ctx->state[15] = LE_READ_UINT32(iv + 4);
}

