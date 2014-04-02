/*
util-opt.h - EARWORM utility functions, optimized implementation
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
#include <x86intrin.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif 

#ifdef __clang__
/* Clang is missing these definitions in <x86intrin.h>, but supports gcc's
   equivalent __builtin_bswapXX() intrinsic */
#undef _bswap
#undef _bswap64
#define _bswap(x) __builtin_bswap32(x)
#define _bswap64(x) __builtin_bswap64(x)
#endif


static inline uint32_t be32dec(const void *buf) {
  return _bswap(*((uint32_t*)buf));
}

static inline void be32enc(void *buf, uint32_t x) {
  *((uint32_t*)buf) = _bswap(x);
}


#ifdef __x86_64__

static inline uint64_t be64dec(const void *buf) {
  return _bswap64(*((uint64_t*)buf));
}

static inline void be64enc(void *buf, uint64_t x) {
  *((uint64_t*)buf) = _bswap64(x);
}

#else /* !__x86_64__ */

static inline uint64_t be64dec(const void *buf) {
  return ((uint64_t)(be32dec(((uint32_t*)buf))) << 32) +
    (uint64_t)(be32dec(((uint32_t*)buf) + 1));
          
}

static inline void be64enc(void *buf, uint64_t x) {
  be32enc(buf, x >> 32);
  be32enc(((uint8_t*)buf) + 4, x & 0xffffffff);
}

#endif


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
  volatile uint64_t *vbuf64 = buf;
  volatile uint32_t *vbuf32 = buf;
  volatile uint8_t *vbuf8 = buf;
  size_t i = 0;
  
  while(i + 7 < size) {
    vbuf64[i >> 3] = 0;
    i+= 8;
  }

  if(i + 3 < size) {
    vbuf32[i >> 2] = 0;
    i += 4;
  }

  while(i < size) {
    vbuf8[i] = 0;
    i++;
  }
}

static inline void xor(void *out, const void *in, size_t size) {
  uint64_t *out64 = out;
  uint32_t *out32 = out;
  uint8_t *out8 = out;

  const uint64_t *in64 = in;
  const uint32_t *in32 = in;
  const uint8_t *in8 = in;

  size_t i = 0;

  while(i + 7 < size) {
    out64[i >> 3] ^= in64[i >> 3];
    i += 8;
  }

  if(i + 3 < size) {
    out32[i >> 2] ^= in32[i >> 2];
    i += 4;
  }

  while(i < size) {
    out8[i] ^= in8[i];
    i++;
  }
}

#ifdef _MSC_VER
#include <malloc.h>
static inline void* malloc16(size_t size) {
  return _aligned_malloc(size, 16);
}
#else
#include <errno.h>
static inline void* malloc16(size_t size) {
  void *mem;
  errno = posix_memalign(&mem, 16, size);
  if(errno == 0)
    return mem;
  return NULL;
}
#endif

#endif
