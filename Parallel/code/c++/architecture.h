// James Nobis <frt AT quelrod DOT net>
// http://www.freerainbowtables.com/phpBB3/topic2465.html
// "Feel free to consider this file to be in the public domain with no (C) attribution necessary."

#ifndef ARCHITECTURE_H
#define ARCHITECTURE_H

#if defined (__GLIBC__)
	#include <endian.h>
	#if (__BYTE_ORDER == __LITTLE_ENDIAN)
		#define ARC_LITTLE_ENDIAN
	#elif (__BYTE_ORDER == __BIG_ENDIAN)
		#define ARC_BIG_ENDIAN
	#else
		#error "Unknown machine endianness"
	#endif
#elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
	#define ARC_BIG_ENDIAN
#elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
	#define ARC_LITTLE_ENDIAN
#elif defined(__sparc)  || defined(__sparc__)   || \
      defined(_POWER)   || defined(__powerpc__) || \
      defined(__ppc__)  || defined(__hpux)      || \
      defined(_MIPSEB)  || defined(_POWER)      || \
      defined(__s390__)
	#define ARC_BIG_ENDIAN
#elif defined(__i386__)  || defined(__alpha__)  || \
      defined(__ia64)    || defined(__ia64__)   || \
      defined(_M_IX86)   || defined(_M_IA64)    || \
      defined(_M_ALPHA)  || defined(__amd64)    || \
      defined(__amd64__) || defined(_M_AMD64)   || \
      defined(__x86_64)  || defined(__x86_64__) || \
      defined(_M_X64)
	#define ARC_LITTLE_ENDIAN
#else
	#error "Unknown machine endianness"
#endif

#if defined(_M_X64) || defined(__x86_64__)
	#define ARC_x86_64
	#define ARC_x86
#elif defined(_M_IX86) || defined(__i386__)
	#define ARC_x86_32
	#define ARC_x86
#endif

#if defined(_LP64)     || defined(__LP64__)   || \
    defined(__ia64)    || defined(__ia64__)   || \
    defined(_M_IA64)   || defined(__amd64)    || \
    defined(__amd64__) || defined(_M_AMD64)   || \
    defined(__x86_64)  || defined(__x86_64__) || \
    defined(_M_X64)    || defined(_WIN64)
	#define ARC_64
#else
	#define ARC_32
#endif

#endif
