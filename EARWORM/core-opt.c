/*
core-opt.c - EARWORM core, reference implementation
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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <x86intrin.h>

#include "util-opt.h"
#include "sha256.h"
#include "core.h"

static void prf(uint8_t *out, size_t outlen,
		const uint8_t *secret, size_t secretlen,
		const uint8_t *salt, size_t saltlen) {
  assert((outlen >> 5) <= UINT32_MAX);
  earworm_PBKDF2_SHA256(secret, secretlen, salt, saltlen, 1, out, outlen);
}

static size_t to_index(const __m128i block, uint32_t m_cost) {
  size_t index;

#ifdef __x86_64__
    index = _bswap64(_mm_extract_epi64(block, 1));
#else
    index = _bswap(_mm_extract_epi32(block, 3));
#endif
    
  index &= ~(~((size_t)0) << m_cost); /* Reduce modulo 2**n. */
  index *= EARWORM_CHUNK_AREA;

  return index;
}

static void workunit(uint8_t *out, size_t outlen,
                     const uint8_t *secret, size_t secretlen,
                     const uint8_t *salt, size_t saltlen,
                     uint32_t m_cost,
                     const __m128i *arena) {

  size_t arena_index_a, arena_index_b;
  __m128i arena_index_tmpbuf[2];
  __m128i scratchpad[EARWORM_CHUNK_WIDTH];
  uint8_t prefixed_salt[EARWORM_MAX_SALT_SIZE + 5];
  size_t d, l, w;

  /* Compute initial arena indexes */
  prefixed_salt[0] = 0x00;
  memcpy(prefixed_salt + 1, salt, saltlen);
  prf((uint8_t*)arena_index_tmpbuf, sizeof arena_index_tmpbuf,
      secret, secretlen,
      prefixed_salt, saltlen+1);
  arena_index_a = to_index(arena_index_tmpbuf[0], m_cost);
  arena_index_b = to_index(arena_index_tmpbuf[1], m_cost);

  _mm_prefetch(&arena[arena_index_a], _MM_HINT_T0);
  _mm_prefetch(&arena[arena_index_b], _MM_HINT_T0);

  secure_wipe(arena_index_tmpbuf, sizeof arena_index_tmpbuf);

  /* Compute initial scratchpad contents */
  prefixed_salt[0] = 0x01;
  prf((uint8_t*)scratchpad, sizeof scratchpad,
      secret, secretlen,
      prefixed_salt, saltlen+1);

  /* Main loop */
  for(d = 0; d < EARWORM_WORKUNIT_DEPTH; d+=2) {
    for(l = 0; l < EARWORM_CHUNK_LENGTH; l++) {
      for(w = 0; w < EARWORM_CHUNK_WIDTH; w++)
        scratchpad[w] = _mm_aesenc_si128(scratchpad[w], arena[arena_index_a++]);
    }
    arena_index_a = to_index(scratchpad[0], m_cost);
    _mm_prefetch(&arena[arena_index_a], _MM_HINT_T0);
    
    for(l = 0; l < EARWORM_CHUNK_LENGTH; l++) {
      for(w = 0; w < EARWORM_CHUNK_WIDTH; w++)
        scratchpad[w] = _mm_aesenc_si128(scratchpad[w], arena[arena_index_b++]);
    }
    arena_index_b = to_index(scratchpad[0], m_cost);
    _mm_prefetch(&arena[arena_index_b], _MM_HINT_T0);
  }
  
  /* Extract output */
  prefixed_salt[0] = 0x02;
  prf(out, outlen,
      (uint8_t*)scratchpad, sizeof scratchpad,
      prefixed_salt, saltlen+1);

  secure_wipe(scratchpad, sizeof scratchpad);
  secure_wipe(&arena_index_a, sizeof arena_index_a);
  secure_wipe(&arena_index_b, sizeof arena_index_b);
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

  workunit_out = malloc(outlen);
  if(workunit_out == NULL)
    return -1;

  memcpy(prefixed_salt + 4, salt, saltlen);
  memset(out, 0, outlen);

  for(i = time_start; i < time_end; i++) {
    be32enc(prefixed_salt, i);
    workunit(workunit_out, outlen,
             secret, secretlen,
             prefixed_salt, saltlen+4,
             m_cost, (__m128i*)arena);
    xor(out, workunit_out, outlen);
  }

  secure_wipe(workunit_out, outlen);
  free(workunit_out);

  return 0;
}
