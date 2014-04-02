/*
util-ref.h - EARWORM utility functions, reference implementation 
Written in 2013 by Daniel Franke <dfoxfranke@gmail.com>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef EARWORM_UTIL_H
#define EARWORM_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif 

static inline uint32_t be32dec(const void *buf) {
  const uint8_t *b = (const uint8_t*)buf;
  return ((uint32_t)(b[0]) << 24) +
    ((uint32_t)(b[1]) << 16) +
    ((uint32_t)(b[2]) << 8) +
    (uint32_t)(b[3]);
}

static inline void be32enc(void *buf, uint32_t x) {
  uint8_t *b = (uint8_t*)buf;
  
  b[0] = (x >> 24) & 0xff;
  b[1] = (x >> 16) & 0xff;
  b[2] = (x >> 8) & 0xff;
  b[3] = x & 0xff;
}

static inline uint64_t be64dec(const void *buf) {
  const uint8_t *b = (const uint8_t*)buf;

  return ((uint64_t)(b[0]) << 56) +
    ((uint64_t)(b[1]) << 48) +
    ((uint64_t)(b[2]) << 40) +
    ((uint64_t)(b[3]) << 32) +
    ((uint64_t)(b[4]) << 24) +
    ((uint64_t)(b[5]) << 16) +
    ((uint64_t)(b[6]) << 8) +
    (uint64_t)(b[7]);
}

static inline void be64enc(void *buf, uint64_t x) {
  uint8_t *b = (uint8_t*)buf;
  
  b[0] = (x >> 56) & 0xff;
  b[1] = (x >> 48) & 0xff;
  b[2] = (x >> 40) & 0xff;
  b[3] = (x >> 32) & 0xff;
  b[4] = (x >> 24) & 0xff;
  b[5] = (x >> 16) & 0xff;
  b[6] = (x >> 8) & 0xff;
  b[7] = x & 0xff;
}

/** Zero out memory through a volatile pointer, preventing the
    compiler from optimizing out the operation if the memory is not
    used afterwards.

    Via email (in the context of a Tarsnap bug report), Colin Percvial
    pointed out the following:

    > [Daniel Franke writes:]

    >> This optimization can be prevented by writing through a volatile
    >> pointer.

    > Unfortunately, no.  Or rather -- yes, that will ensure that
    > *some* memory is zeroed; but it does nothing to ensure that the
    > memory which is zeroed contains the only copy of the sensitive
    > data.  Compilers can (and often do) keep multiple copies of data
    > or keep data in different locations at different times -- gcc's
    > register allocator is a particular culprit here, as it can
    > assign values to "registers", then find that it doesn't have
    > enough registers, and map those to locations on the stack, thus
    > creating a lot of work copying values between stack and external
    > arrays -- so merely zeroing *a* buffer does not solve the
    > problem at all.

    > I'm hoping that at some point we'll see language extensions to
    > mark data as "tainted" so that it can be reliably zeroed, but
    > that functionality does not exist at present.  Until it does
    > exist, this is a "can't fix" problem.

    In spite of this difficulty, I'm still making use of this
    function, per recommendations agreed upon on the PHC mailing list.
    Maybe it'll at least accomplish its goal *some* of the time.

*/
static inline void secure_wipe(void *buf, size_t size) {
  volatile uint8_t *vbuf = buf;
  size_t i;
  
  for(i=0; i < size; i++)
    vbuf[i] = 0;
}

static inline void xor(void *out, const void *in, size_t size) {
  size_t i;
  for(i=0; i < size; i++)
    ((uint8_t*)out)[i] ^= ((uint8_t*)in)[i];
}


/* malloc16 is a function for allocating 16-byte aligned memory. However,
   the reference implementation doesn't *need* aligned memory, so here
   we just make it an alias for malloc. */
#define malloc16 malloc

#endif
