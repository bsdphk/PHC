/*
core.h - EARWORM core
Written in 2013 by Daniel Franke <dfoxfranke@gmail.com>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef EARWORM_CORE_H
#define EARWORM_CORE_H

#include <assert.h>
#include "util.h"

#define EARWORM_CHUNK_LENGTH ((size_t)64)
#define EARWORM_CHUNK_WIDTH ((size_t)4)
#define EARWORM_CHUNK_AREA (EARWORM_CHUNK_LENGTH * EARWORM_CHUNK_WIDTH)
#define EARWORM_WORKUNIT_DEPTH ((size_t)256)
#define EARWORM_MAX_SALT_SIZE ((size_t)32)

static inline int validate_fit(size_t chunk_area, uint32_t m_cost) {
  if(SIZE_MAX >> (m_cost + 4) >= chunk_area - 1)
    return 0;
  else return -1;
}

static inline size_t arena_size(size_t chunk_area, uint32_t m_cost) {
  assert(validate_fit(chunk_area, m_cost) == 0);
  return (size_t)chunk_area << (m_cost + 4);
}

int earworm_core(void *out, size_t outlen,
                 const void *secret, size_t secretlen,
                 const void *salt, size_t saltlen,
                 unsigned int m_cost,
                 uint32_t time_start, uint32_t time_end,
                 const void *arena);

#endif /* !EARWORM_CORE_H */
