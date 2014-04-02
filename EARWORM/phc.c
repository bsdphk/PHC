/*
phc.c - PHC API for EARWORM
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
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "aes.h"
#include "util.h"

#define AES_BLOCK_SIZE ((size_t)16)

static const void* get_test_arena(unsigned int m_cost) {
  static uint8_t* test_arena = NULL;
  static unsigned int last_mcost;
  static const uint8_t testseed[32] = {
    'd', 'o', 'n', '\'', 't', ' ', 'u', 's',
    'e', ' ', 't', 'h',  'i', 's', ' ', 'k',
    'e', 'y', ' ', 'i', 'n',  ' ', 'p', 'r', 
    'o', 'd', 'u', 'c', 't',  'i', 'o', 'n'
  };
  static aeskey_t key;
  size_t i;

  if(test_arena != NULL && m_cost <= last_mcost)
    return test_arena;

  if(validate_fit(EARWORM_CHUNK_AREA, m_cost) != 0)
    return NULL;

  free(test_arena);
  test_arena = malloc16(arena_size(EARWORM_CHUNK_AREA, m_cost));
  if(test_arena == NULL)
    return NULL;

  earworm_aes256enc_keysetup(testseed, &key);

  for(i = 0;
      i < EARWORM_CHUNK_AREA << m_cost;
      i++) {
    memset(test_arena + AES_BLOCK_SIZE * i, 0, 8);
    be64enc(test_arena + AES_BLOCK_SIZE * i + 8, i);
    earworm_aes256enc(test_arena + AES_BLOCK_SIZE * i, &key);
  };

  last_mcost = m_cost;
  return test_arena;
}

int PHS_initialize_arena(unsigned int m_cost) {
  if(get_test_arena(m_cost) == NULL)
    return -1;
  return 0;
}

int PHS(void *out, size_t outlen, 
        const void *in, size_t inlen,
        const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {

  if(saltlen > EARWORM_MAX_SALT_SIZE ||
     t_cost < 1 ||
     t_cost > UINT32_MAX)
    return -1;

  const uint8_t *arena = get_test_arena(m_cost);

  if(arena == NULL)
    return -1;

  return earworm_core(out, outlen, in, inlen, salt, saltlen,
                      m_cost, 0, t_cost, arena);
}
