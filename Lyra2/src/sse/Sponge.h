/*
   
        Implementation of a sponge function that uses the F function from Blake2b.
  
   LYRA2 reference source code package - SSE optimized implementation - <http://www.lyra-kdf.net/>

   Written in 2014 by Leonardo de Campos Almeida <lalmeida@larc.usp.br>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
*/
#ifndef SPONGE_H_
#define SPONGE_H_

#include <stdint.h>
#include <emmintrin.h>


#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

/*Blake 2b IV Array*/
static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};


static inline uint64_t rotr64( const uint64_t w, const unsigned c ){
    return ( w >> c ) | ( w << ( 64 - c ) );
}

/*Blake's G function*/
#define G(r,i,a,b,c,d) \
  do { \
    a = a + b; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
  } while(0)


/*One Round of the Blake's 2 compression function*/
#define ROUND_LYRA(r)  \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]);

/**
 * Initializes the Sponge State. The first 512 bits are set to zeros and the remainder 
 * receive Blake2b's IV as per Blake2b's specification. <b>Note:</b> Even though sponges
 * typically have their internal state initialized with zeros, Blake2b's G function
 * has a fixed point: if the internal state and message are both filled with zeros. the 
 * resulting permutation will always be a block filled with zeros; this happens because 
 * Blake2b does not use the constants originally employed in Blake2 inside its G function, 
 * relying on the IV for avoiding possible fixed points.
 * 
 * @param state         The 1024-bit array to be initialized
 */
void initStateSSE(__m128i state[/*8*/]);

void squeezeSSE(__m128i *state, unsigned char *out, unsigned int len);
void absorbBlockSSE(__m128i *state, const __m128i *in);
void squeezeBlockSSE(__m128i* state, __m128i* block);
void absorbPaddedSaltSSE(__m128i *state, const unsigned char *salt);
void reducedSqueezeRowSSE(__m128i* state, __m128i* row, int nCols);
void reducedDuplexRowSSE(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut, int nCols);
void reducedDuplexRowSetupSSE(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut, int nCols);

void printArray(unsigned char *array, unsigned int size, char *name);

#endif /* SPONGE_H_ */
