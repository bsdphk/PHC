/*
core-ref.c - EARWORM core, reference implementation
Written in 2013 by Daniel Franke <dfoxfranke@gmail.com>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util-ref.h"
#include "aes.h"
#include "sha256.h"
#include "core.h"

#define AES_BLOCK_SIZE ((size_t)16)

static void prf(uint8_t *out, size_t outlen,
		const uint8_t *secret, size_t secretlen,
		const uint8_t *salt, size_t saltlen) {
  assert((outlen >> 5) <= UINT32_MAX);
  earworm_PBKDF2_SHA256(secret, secretlen, salt, saltlen, 1, out, outlen);
}

static size_t to_index(const uint8_t *buf,unsigned int m_cost) {
  size_t index = 0;
  size_t i;
  
  assert(validate_fit(EARWORM_CHUNK_AREA, m_cost) == 0);
  
  /* This will overflow, which is okay. */
  for(i = 0; i < AES_BLOCK_SIZE; i++) {
    index <<= 8;
    index += buf[i];
  }
  
  index &= ~(~((size_t)0) << m_cost); /* Reduce modulo 2**m_cost. */
  index *= EARWORM_CHUNK_AREA;

  return index;
}

static void workunit(uint8_t *out, size_t outlen,
                     const uint8_t *secret, size_t secretlen,
                     const uint8_t *salt, size_t saltlen,
                     unsigned int m_cost,
                     const uint8_t *arena) {

  uint8_t scratchpad[AES_BLOCK_SIZE * EARWORM_CHUNK_WIDTH];
  uint8_t prefixed_salt[EARWORM_MAX_SALT_SIZE + 5];
  uint8_t arena_index_tmpbuf[AES_BLOCK_SIZE * 2];
  size_t arena_index[2];
  size_t d, l, w;

  assert(validate_fit(EARWORM_CHUNK_AREA, m_cost) == 0);
  assert(outlen <= UINT32_MAX);
  assert(secretlen <= UINT32_MAX);
  assert(saltlen <= EARWORM_MAX_SALT_SIZE + 4);

  /* Compute initial array indexes */
  prefixed_salt[0] = 0x00;
  memcpy(prefixed_salt + 1, salt, saltlen);
  prf(arena_index_tmpbuf, sizeof arena_index_tmpbuf,
      secret, secretlen,
      prefixed_salt, saltlen+1);
  arena_index[0] = to_index(arena_index_tmpbuf, m_cost);
  arena_index[1] = to_index(arena_index_tmpbuf + AES_BLOCK_SIZE, m_cost);
  secure_wipe(arena_index_tmpbuf, sizeof arena_index_tmpbuf);

  /* Compute initial scratchpad contents */
  prefixed_salt[0] = 0x01;
  prf(scratchpad, sizeof scratchpad, secret, secretlen,
      prefixed_salt, saltlen+1);

  /* Main loop */
  for(d = 0; d < EARWORM_WORKUNIT_DEPTH; d++) {
    for(l = 0; l < EARWORM_CHUNK_LENGTH; l++) {
      for(w = 0; w < EARWORM_CHUNK_WIDTH; w++)
        earworm_aesenc_round(scratchpad + AES_BLOCK_SIZE * w,
                             arena + AES_BLOCK_SIZE * arena_index[0]++);
    }
    arena_index[0] = to_index(scratchpad, m_cost);

    if(++d == EARWORM_WORKUNIT_DEPTH)
      break;
    
    for(l = 0; l < EARWORM_CHUNK_LENGTH; l++) {
      for(w = 0; w < EARWORM_CHUNK_WIDTH; w++)
        earworm_aesenc_round(scratchpad + AES_BLOCK_SIZE * w,
                             arena + AES_BLOCK_SIZE * arena_index[1]++);
    }
    arena_index[1] = to_index(scratchpad, m_cost);
  }
  
  /* Extract output */
  prefixed_salt[0] = 0x02;
  prf(out, outlen, scratchpad, sizeof scratchpad, prefixed_salt, saltlen+1);

  secure_wipe(scratchpad, sizeof scratchpad);
  secure_wipe(arena_index, sizeof arena_index);
}

int earworm_core(void *out, size_t outlen,
                 const void *secret, size_t secretlen,
                 const void *salt, size_t saltlen,
                 unsigned int m_cost,
                 uint32_t time_start,
                 uint32_t time_end,
                 const void *arena) {

  uint8_t *workunit_out;
  uint8_t prefixed_salt[EARWORM_MAX_SALT_SIZE+4];
  uint32_t i;

  assert(validate_fit(EARWORM_CHUNK_AREA, m_cost) == 0);  
  assert(time_start <= time_end);
  assert(outlen <= UINT32_MAX);
  assert(secretlen <= UINT32_MAX);
  assert(saltlen <= EARWORM_MAX_SALT_SIZE);
  assert(out != NULL);
  assert(secret != NULL);
  assert(salt != NULL);

  workunit_out = malloc(outlen);
  if(workunit_out == NULL)
    return -1;

  memcpy(prefixed_salt + 4, salt, saltlen);
  memset(out, 0, outlen);

  for(i = time_start; i < time_end; i++) {
    be32enc(prefixed_salt, i);
    workunit(workunit_out, outlen, secret, secretlen,
             prefixed_salt, saltlen+4, m_cost, arena);
    xor(out, workunit_out, outlen);
  }

  secure_wipe(workunit_out, outlen);
  free(workunit_out);
  return 0;
}
