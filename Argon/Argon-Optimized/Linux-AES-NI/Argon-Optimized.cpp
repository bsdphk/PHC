// Argon-Optimized.cpp
// Optimized code for Windows x86/x64 architectures. Produced with Visual Studio 2013 Express
// Code written by Dmitry Khovratovich, khovratovich@gmail.com, and Yann Le Corre
// Requires C++11
//To fileprint intermediate variables, uncomment #define KAT
//To enable measurement of SubGroups and ShuffleSlices, uncomment #define _MEASUREINT
//To disable threading, comment #define THREADING

//#define ARGON_TEST
//#define KAT
//#define KAT_INTERNAL
#define _MEASURE
//#define _MEASUREINT 
#define THREADING

#include "stdio.h"

#include <time.h>
#include <vector>
#include <thread>
#include <cstring>
#include <cstdint>
using namespace std;

#define MAX_THREADS 32
#define MAX_OUTLEN 32
#define MIN_MEMORY 1
#define MAX_MEMORY (1<<26)
#define MIN_TIME 1
#define LENGTH_SIZE 4
#define MIN_PASSWORD 0
#define MAX_PASSWORD 256
#define MAX_SALT  32
#define MAX_SECRET 16
#define INPUT_SIZE (INPUT_BLOCKS*12)
#define INPUT_BLOCKS 32
#define CACHE_SIZE 16
#define MAX_CACHE 128
#define BATCH_SIZE 16   //should be not larger than 32
#define GROUP_SIZE 32

#define AES_ROUNDS 5

#ifdef __GNUG__
	#include <x86intrin.h>
#endif



unsigned char subkeys[11][16]={
	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, },
{0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe, },
{0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe, },
{0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41, },
{0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd, },
{0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa, },
{0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b, },
{0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26, },
{0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2, },
{0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e, },
	{0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5, }};

uint64_t subkeys64[11][2]=
	{{0x0706050403020100, 0x0f0e0d0c0b0a0908},
{0xfa72afd2fd74aad6, 0xfe76abd6f178a6da},
{0xf1bd3d640bcf92b6, 0xfeb3306800c59bbe},
{0xbfc9c2d24e74ffb6, 0x41bf6904bf0c596c},
{0x033e3595bcf7f747, 0xfd8d05fdbc326cf9},
{0xeb9d9fa9e8a3aa3c, 0xaa22f6ad57aff350},
{0x9692a6f77d0f395e, 0x6b1fa30ac13d55a7},
{0x8ce25fe31a70f914, 0x26c0a94e4ddf0a44},
{0xb9651ca435874347, 0xd27abfaef4ba16e0},
{0x685785f0d1329954, 0x4e972cbe9ced9310},
{0x174a94e37f1d1113, 0xc5302b4d8ba707f3}};

void dumpState(FILE *fp, __m128i *state, size_t state_size)
{
	for(size_t i = 0; i < state_size; ++i)
	{
		uint64_t u0 = (uint64_t)_mm_extract_epi64(state[i], 0);
		uint64_t u1 = (uint64_t)_mm_extract_epi64(state[i], 1);
		fprintf(fp,"Block %3.3lu: H: %.16lx L: %.16lx\n", i, u1, u0);
	}
}

struct int128{
	uint64_t i0,i1;
	int128(uint64_t y0=0, uint64_t y1=0){i0 = y0; i1 = y1;};
	int128& operator^=(const int128 &r){ i0 ^= r.i0; i1 ^=r.i1; return *this;}
	int128& operator=(const int128 &r){ i0 = r.i0; i1 =r.i1; return *this;}
	unsigned char operator[](unsigned i)
	{
		if(i<8)
			return (i0>>(8*i))&0xff;
		else if(i<16)
			return (i1>>(8*(i-8)))&0xff;
		return 0;
	}
	int128 operator^(const int128 &r){ return int128(i0 ^ r.i0,i1^r.i1); }
};

inline void AES_reduced_opt(int128 &u)
{
//Round Key initialization
	__m128i roundkey[AES_ROUNDS+1];
	
	for(unsigned i=0; i<AES_ROUNDS+1; ++i)
	{
		roundkey[i]=_mm_set_epi64x(subkeys64[i][1],subkeys64[i][0]); 
	}

	__m128i acc0 = _mm_set_epi64x(u.i1,u.i0);
	
	acc0 = _mm_xor_si128(acc0, roundkey[0]);
	
	for(unsigned j=0; j<AES_ROUNDS; ++j)
	{
		for(unsigned i=0; i<1; ++i)
		{
			acc0 = _mm_aesenc_si128(acc0, roundkey[j+1]);
		}
	}
	{	
		u.i0 = _mm_extract_epi64(acc0, 0);
		u.i1 = _mm_extract_epi64(acc0, 1);
	}
}




//AES S-box
const static unsigned char sbox[256] =   {
		//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };


void ShuffleSlicesThr(__m128i* state, size_t slice_length, unsigned slices)
{
	for(unsigned s=0; s<slices; ++s) //Loop on slices
	{
		size_t j = 0;
		for(uint32_t i=0; i<slice_length; ++i)
		{
			size_t index1 = s*(slice_length)+i;
			__m128i v1 = state[index1];
			int32_t q = _mm_extract_epi32(v1, 0);
			j = (j+ q) % slice_length;
			size_t index2 = s*(slice_length)+j;
			state[index1]=state[index2];
			state[index2] = v1;
		}
	}
}


void ShuffleSlicesThr2(__m128i* state, size_t slice_length, unsigned slices)
{
	for(unsigned s=0; s<slices; s+=2) //Loop on slices
	{
		size_t j[2];
		j[0] = j[1] = 0;
		size_t index1[2];
		size_t index2[2];
		__m128i v1[2];
		int32_t tmp;
		for (size_t i = 0; i<slice_length; ++i)
		{
			index1[0] = s*(slice_length) + i; 
			index1[1] = (s+1)*(slice_length) + i; 
			v1[0] = state[index1[0]];
			v1[1] = state[index1[1]];
			tmp = _mm_extract_epi32(v1[0], 0);
			j[0] = (j[0]+ tmp) % slice_length;
			tmp = _mm_extract_epi32(v1[1], 0);
			j[1] = (j[1]+ tmp) % slice_length;
			index2[0] = s*(slice_length)+j[0];
			index2[1] = (s+1)*(slice_length)+j[1];
			state[index1[0]]=state[index2[0]];
			state[index1[1]]=state[index2[1]];
			state[index2[0]] = v1[0];
			state[index2[1]] = v1[1];
		}
	}
}

void ShuffleSlicesIntr(__m128i* state, size_t width)
{
	for(unsigned s=0; s<GROUP_SIZE; ++s) //Loop on slices
	{
		size_t j=0;
		for(uint32_t i=0; i<width/GROUP_SIZE; ++i)
		{
			size_t index1 = s*(width/GROUP_SIZE) + i; 
			__m128i v1 = state[index1];
			int32_t q = _mm_extract_epi32(v1, 0);
			j = (j+ q) % (width/GROUP_SIZE);
			size_t index2 = s*(width/GROUP_SIZE)+j;
			state[index1]=state[index2];
			state[index2] = v1;
		}
	}
}


inline void AES_reduced_batch_intr(__m128i* batch) //Encrypts BATCH_SIZE in parallel
{
//Round Key initialization
	__m128i roundkey[AES_ROUNDS+1];
	
	for(unsigned i=0; i<AES_ROUNDS+1; ++i)
	{
		roundkey[i] = _mm_set_epi64x(subkeys64[i][1],subkeys64[i][0]);
	}
	for(unsigned i=0; i<BATCH_SIZE; ++i)
	{
		batch[i] = _mm_xor_si128(batch[i],roundkey[0]);
	}
	
	for(unsigned j=0; j<AES_ROUNDS; ++j)
	{
		for(unsigned i=0; i<BATCH_SIZE; ++i)
		{
			batch[i] = _mm_aesenc_si128(batch[i], roundkey[j+1]);
		}
	}
	
}

void SubGroupsIntr(__m128i* state, size_t width)
{
	__m128i groups[MAX_CACHE][GROUP_SIZE];
	unsigned cached=0;
	if(width < (CACHE_SIZE*GROUP_SIZE))
		cached = (unsigned)width/GROUP_SIZE;
	else
		cached = CACHE_SIZE;
	for(uint32_t i=0; i<width/GROUP_SIZE; i+=cached)
	{
		//Storing group inputs
		for(unsigned l=0; l<GROUP_SIZE; ++l)
		{
			for(unsigned j=0; j<cached; ++j)
			{
				groups[j][l]= state[i+j+l*(width/32)];
			}
		}
		for(unsigned j=0; j<cached; ++j)
		{
			//Computing X_i:
			__m128i X[16];
			X[ 0] = _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][23], _mm_xor_si128(groups[j][27], groups[j][31])))))));
			X[ 1] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][25], groups[j][27])))))));
			X[ 2] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][20], groups[j][22])))))));
			X[ 3] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][13], groups[j][15])))))));
			X[ 4] = _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][22], _mm_xor_si128(groups[j][23], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 5] = _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][26], _mm_xor_si128(groups[j][27], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 6] = _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][24], _mm_xor_si128(groups[j][25], _mm_xor_si128(groups[j][28], groups[j][29])))))));
			X[ 7] = _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][28], _mm_xor_si128(groups[j][29], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 8] = _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][14], groups[j][15])))))));
			X[ 9] = _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][22], groups[j][23])))))));
			X[10] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][25], groups[j][29])))))));
			X[11] = _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][22], _mm_xor_si128(groups[j][26], groups[j][30])))))));
			X[12] = _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][22], groups[j][23])))))));
			X[13] = _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][24], _mm_xor_si128(groups[j][25], _mm_xor_si128(groups[j][26], groups[j][27])))))));
			X[14] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][10], groups[j][11])))))));
			X[15] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][24], groups[j][28])))))));

			

			for(unsigned k=0; k<16;k+=BATCH_SIZE)
			{
				AES_reduced_batch_intr(X+k);//Computing F's
			}
			for(unsigned k=0; k<16;++k)
			{
				groups[j][2*k] =  _mm_xor_si128(groups[j][2*k],X[k]); //XORs
				groups[j][2*k+1] = _mm_xor_si128(groups[j][2*k+1],X[k]); 
			}
			for(unsigned k=0; k<32;k+=BATCH_SIZE)
			{
				AES_reduced_batch_intr(groups[j]+k);//Computing F's
			}
		}//end of group computation
		for(unsigned l=0; l<32; ++l)
		{
			for(unsigned j=0; j<cached; ++j)
			{
				state[i+j+l*(width/32)]=groups[j][l];
			}
		}
	}
}


void SubGroupsThr(__m128i* state, size_t group_n, size_t distance) //elements of the group are 'distance' blocks from each other in memory
{

	__m128i groups[MAX_CACHE][GROUP_SIZE];
	size_t cached=0;
	cached = (group_n<CACHE_SIZE) ? group_n : CACHE_SIZE;
	for (size_t i = 0; i<group_n; i += cached)
	{
		//Storing group inputs
		if(group_n< cached+i)
			cached = (group_n-i);
		for(unsigned l=0; l<GROUP_SIZE; ++l)
		{
			for (size_t j = 0; j<cached; ++j)
			{
				groups[j][l]= state[i+j+l*distance];
			}
		}
		for(unsigned j=0; j<cached; ++j)
		{
			//Computing X_i:
			__m128i X[16];
			X[ 0] = _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][23], _mm_xor_si128(groups[j][27], groups[j][31])))))));
			X[ 1] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][25], groups[j][27])))))));
			X[ 2] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][20], groups[j][22])))))));
			X[ 3] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][13], groups[j][15])))))));
			X[ 4] = _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][22], _mm_xor_si128(groups[j][23], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 5] = _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][26], _mm_xor_si128(groups[j][27], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 6] = _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][24], _mm_xor_si128(groups[j][25], _mm_xor_si128(groups[j][28], groups[j][29])))))));
			X[ 7] = _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][15], _mm_xor_si128(groups[j][28], _mm_xor_si128(groups[j][29], _mm_xor_si128(groups[j][30], groups[j][31])))))));
			X[ 8] = _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][14], groups[j][15])))))));
			X[ 9] = _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][19], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][22], groups[j][23])))))));
			X[10] = _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][13], _mm_xor_si128(groups[j][17], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][25], groups[j][29])))))));
			X[11] = _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][14], _mm_xor_si128(groups[j][18], _mm_xor_si128(groups[j][22], _mm_xor_si128(groups[j][26], groups[j][30])))))));
			X[12] = _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 5], _mm_xor_si128(groups[j][ 6], _mm_xor_si128(groups[j][ 7], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][21], _mm_xor_si128(groups[j][22], groups[j][23])))))));
			X[13] = _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][10], _mm_xor_si128(groups[j][11], _mm_xor_si128(groups[j][24], _mm_xor_si128(groups[j][25], _mm_xor_si128(groups[j][26], groups[j][27])))))));
			X[14] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 1], _mm_xor_si128(groups[j][ 2], _mm_xor_si128(groups[j][ 3], _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][ 9], _mm_xor_si128(groups[j][10], groups[j][11])))))));
			X[15] = _mm_xor_si128(groups[j][ 0], _mm_xor_si128(groups[j][ 4], _mm_xor_si128(groups[j][ 8], _mm_xor_si128(groups[j][12], _mm_xor_si128(groups[j][16], _mm_xor_si128(groups[j][20], _mm_xor_si128(groups[j][24], groups[j][28])))))));



			

			for(unsigned k=0; k<16;k+=BATCH_SIZE)
			{
				AES_reduced_batch_intr(X+k);//Computing F's
			}
			for(unsigned k=0; k<16;++k)
			{
				groups[j][2*k] =  _mm_xor_si128(groups[j][2*k],X[k]); //XORs
				groups[j][2*k+1] = _mm_xor_si128(groups[j][2*k+1],X[k]); 
			}
			for(unsigned k=0; k<32;k+=BATCH_SIZE)
			{
				AES_reduced_batch_intr(groups[j]+k);//Computing F's
			}
		}//end of group computation
		for(unsigned l=0; l<32; ++l)
		{
			for(unsigned j=0; j<cached; ++j)
			{
				state[i+j+l*distance]=groups[j][l];
			}
		}
	}
}

void InitialRound(__m128i* state, size_t state_size)
{
	for(uint32_t i=0; i<state_size; i+=BATCH_SIZE)
	{
		AES_reduced_batch_intr(state+i);
	}
}

int ArgonFast64(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, const void *secret, size_t secretlen, uint32_t t_cost, size_t m_cost,uint32_t thread_n=2)
{
	__m128i* state;
#ifdef KAT
	FILE* fp=fopen("kat-opt.log","a+");
	
	fprintf(fp,"OPTIMIZED:\nT_cost: %u, Memory: %lu KBytes\n", t_cost, m_cost);
#endif
	#ifdef _MEASUREINT
	uint64_t  i1,i2,i3,i4,i5,i6,d1,d2;
	uint32_t ui1,ui2,ui3,ui4,ui6;
	i1 = __rdtscp(&ui1);
#endif
	//Computing parameters
	//maximum outlen=32
	if(outlen>MAX_OUTLEN)
		outlen=MAX_OUTLEN;

	//minumum m_cost =1
	if(m_cost<MIN_MEMORY)
		m_cost = MIN_MEMORY;
	if(m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;
	
	//minimum t_cost =3
	if(t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if(inlen> MAX_PASSWORD)
		inlen = MAX_PASSWORD;
	if(saltlen> MAX_SALT)
		saltlen = MAX_SALT;
	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;
	if(thread_n ==0)
		thread_n =1;
	if(thread_n > MAX_THREADS)
		thread_n = MAX_THREADS;
#ifdef KAT
	fprintf(fp,"Password: ");
	for(unsigned i=0; i<inlen; ++i)
		fprintf(fp,"%2.2x ",((unsigned char*)in)[i]);
	fprintf(fp,"\n");
	fprintf(fp,"Salt: ");
	for(unsigned i=0; i<saltlen; ++i)
		fprintf(fp,"%2.2x ",((unsigned char*)salt)[i]);
	fprintf(fp,"\n");
		
#endif



	//1. Filling input
	unsigned char Input[INPUT_SIZE];
	//1.1 Password length
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i] = (inlen>>(8*i))&0xff;
	}
	//1.2 Salt length
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+LENGTH_SIZE] = (saltlen>>(8*i))&0xff;
	}
	//1.3 Secret length  -- equal to 0 in the default function
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+2*LENGTH_SIZE] =(secretlen>>(8*i))&0xff;
	}
	//1.4 Iteration number
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+3*LENGTH_SIZE] =(t_cost>>(8*i))&0xff;
	}
	//1.5 Memory parametrer
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+4*LENGTH_SIZE] =(m_cost>>(8*i))&0xff;
	}
	//1.6 Tag length
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+5*LENGTH_SIZE] =(outlen>>(8*i))&0xff;
	}
	//1.7 Password
	for(unsigned i=0; i<inlen; ++i)
	{
		Input[i+6*LENGTH_SIZE] =((unsigned char*)in)[i];
	}
	//1.8 Salt
	for(unsigned i=0; i<saltlen; ++i)
	{
		Input[i+6*LENGTH_SIZE+inlen] =((unsigned char*)salt)[i];
	}
	//1.9 Secret
	for(unsigned i=0; i<secretlen; ++i)
	{
		Input[i+6*LENGTH_SIZE+inlen+saltlen+i] =((unsigned char*)secret)[i];
	}
	//1.10 Padding
	for(unsigned i=6*LENGTH_SIZE+(unsigned)(inlen+saltlen+secretlen); i<INPUT_SIZE; ++i)
		Input[i] = 0;
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"Input string:\n");
	for(unsigned i=0; i<INPUT_SIZE; ++i)
	{
		fprintf(fp,"%2.2x ",Input[i]);
		if(i%30==29)
			fprintf(fp,"\n");
	}
	fprintf(fp,"\n");
		
#endif


	//2. Filling blocks
	size_t state_size = m_cost*64;
#ifdef _MEASUREINT
			i3 = __rdtscp(&ui3);
			d1 = (i3-i1)/(state_size);
			printf("First phase %2.2f cpb\n", (float)d1/(16));
#endif
	state = new __m128i[state_size];
	if(state==NULL)
		return 1;
	printf("Memory allocated: %lu MBytes, %d threads\n",(state_size*sizeof(int128)/(1<<20)),thread_n);

	size_t width = state_size/GROUP_SIZE;
	
	for(unsigned i=0; i<GROUP_SIZE; ++i)
	{
		/* All those could be optimized a lot using movd* instructions */
		__m128i tmp;
		size_t start=width*i;
		tmp = _mm_xor_si128(tmp, tmp);

		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  0],  0);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  1],  1);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  2],  2);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  3],  3);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  4],  4);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  5],  5);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  6],  6);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  7],  7);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  8],  8);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i +  9],  9);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i + 10], 10);
		tmp = _mm_insert_epi8(tmp, (int)Input[12*i + 11], 11);
		tmp = _mm_insert_epi32(tmp, (int64_t)i, 3);

		for(uint32_t l=0; l<width; l++)
		{
			state[start+l] = tmp;
			uint32_t c = (uint32_t)_mm_extract_epi32(tmp, 3);
			c += GROUP_SIZE;
			tmp = _mm_insert_epi32(tmp, c, 3);
		}
	}

	memset(Input,0,INPUT_SIZE);
#ifdef _MEASUREINT
			i2 = __rdtscp(&ui2);
			d1 = (i2-i3)/(state_size);
			printf("Filling phase %2.2f cpb\n", (float)d1/(16));
#endif
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"Blocks:\n");
	dumpState(fp, state, state_size);
#endif

	//3. Initial transformation
#ifdef THREADING
	vector<thread> Threads;

	size_t step = state_size/thread_n;//Area size of each thread. Must be divisible by BATCH_SIZE
	step = (step/BATCH_SIZE)*BATCH_SIZE;
	for(unsigned i=0; i<thread_n-1; ++i)
		Threads.push_back(thread(InitialRound,state+i*step, step));
	//Last thread with posssibly larger area
	Threads.push_back(thread(InitialRound, state + (thread_n - 1)*step, state_size - (thread_n - 1)*step));
	for (auto& th: Threads)
		th.join();
	Threads.clear();
#else
	InitialRound(state,state_size);
#endif

	#ifdef _MEASUREINT
			i4 = __rdtscp(&ui4);
			d1 = (i4-i2)/(state_size);
			printf("Initial phase %2.2f cpb\n", (float)d1/(16));
#endif
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"Initial transformation:\nBlocks:\n");
	dumpState(fp, state, state_size);
#endif

	//4. Rounds: 
	for(unsigned l=0; l <t_cost; ++l)
	{
#ifdef THREADING
		//Each thread processes a certain number of groups
		size_t distance = state_size/GROUP_SIZE;
		size_t groups_per_thread = distance/(thread_n);//Area size of each thread.
		for(unsigned i=0; i<thread_n-1; ++i)
			Threads.push_back(thread(SubGroupsThr,state+i*groups_per_thread,groups_per_thread, distance));
		//Last thread with possibly larger area
		Threads.push_back(thread(SubGroupsThr, state + (thread_n - 1)*groups_per_thread, distance - (thread_n - 1)*groups_per_thread, distance));
		for (auto& th : Threads)
			th.join();
		Threads.clear();
#else
		SubGroupsIntr(state,state_size);
#endif
#ifdef _MEASUREINT
			i5 = __rdtscp(&ui3);
			d1 = (i5-i4)/(state_size);
			printf("SubGroups %2.2f cpb\n", (float)d1/(16));
#endif
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"Round %d SubGroups:\nBlocks:\n",l+1);
	dumpState(fp, state, state_size);
#endif
#ifdef THREADING
	unsigned slices_per_thread = GROUP_SIZE/thread_n;//Area size of each thread.
	size_t slice_length = state_size / GROUP_SIZE;
	for(unsigned i=0; i<thread_n-1; ++i)
			Threads.push_back(thread(ShuffleSlicesThr,state+i*slices_per_thread*slice_length,slice_length, slices_per_thread));
	//Last thread
	Threads.push_back(thread(ShuffleSlicesThr, state + (thread_n - 1)*slices_per_thread*slice_length, slice_length, GROUP_SIZE - (thread_n - 1)*slices_per_thread));
	//Wrapping up
	for (auto& th : Threads)
		th.join();
	Threads.clear();

#else
		ShuffleSlicesIntr(state,state_size);
#endif
#ifdef _MEASUREINT
			i4 = __rdtscp(&ui4);
			d1 = (i4-i5)/(state_size);
			printf("ShuffleSlices %2.2f cpb\n", (float)d1/(16));
#endif
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"ShuffleSlices:\nBlocks:\n");
	dumpState(fp, state, state_size);
#endif
	}

	//5.Finalization
#ifdef THREADING
		//Each thread processes a certain number of groups
		size_t distance = state_size / GROUP_SIZE;
		size_t groups_per_thread = distance/(thread_n);//Area size of each thread.
		for(unsigned i=0; i<thread_n-1; ++i)
			Threads.push_back(thread(SubGroupsThr,state+i*groups_per_thread,groups_per_thread, distance));
		//Last thread with posssibly larger area
		Threads.push_back(thread(SubGroupsThr, state + (thread_n - 1)*groups_per_thread, distance - (thread_n - 1)*groups_per_thread, distance));
		for (auto& th : Threads)
			th.join();
		Threads.clear();
#else
		SubGroupsIntr(state,state_size);
#endif
#if defined(KAT) && defined(KAT_INTERNAL)
	fprintf(fp,"Last round: SubGroups:\nBlocks:\n");
	dumpState(fp, state, state_size);
#endif
		#ifdef _MEASUREINT
			i5 = __rdtscp(&ui4);
#endif
	__m128i a1_intr;
	a1_intr = _mm_xor_si128(a1_intr,a1_intr);
	__m128i a2_intr;
	a2_intr = _mm_xor_si128(a2_intr,a2_intr);
	for(uint32_t i=0; i< state_size; ++i)
	{
		if(i%(state_size/32)<state_size/64)   //First w/64 of each slice of size w/32
			a1_intr = _mm_xor_si128(a1_intr, state[i]);
		else 
			a2_intr = _mm_xor_si128(a2_intr, state[i]);
	}
	int128 a1(_mm_extract_epi64(a1_intr, 0), _mm_extract_epi64(a1_intr, 1));
	int128 a2(_mm_extract_epi64(a2_intr, 0), _mm_extract_epi64(a2_intr, 1));
	if(outlen<=16)
	{
		int128 tag = a1^a2;
		AES_reduced_opt(tag);
		AES_reduced_opt(tag);
		AES_reduced_opt(tag);
		AES_reduced_opt(tag);
		tag ^= a1^a2;
		for(unsigned i=0; i<outlen; ++i)
			((unsigned char*)out)[i] = tag[i];
	}
	else
	{
		int128 tag1=a1;
		AES_reduced_opt(tag1);
		AES_reduced_opt(tag1);
		AES_reduced_opt(tag1);
		AES_reduced_opt(tag1);
		tag1 ^= a1;
		for(unsigned i=0; i<16; ++i)
			((unsigned char*)out)[i] = tag1[i];
		int128 tag2=a2;
		AES_reduced_opt(tag2);
		AES_reduced_opt(tag2);
		AES_reduced_opt(tag2);
		AES_reduced_opt(tag2);
		tag2 ^= a2;
		for(unsigned i=16; i<outlen; ++i)
			((unsigned char*)out)[i] = tag2[i-16];
	}
		#ifdef _MEASUREINT
			i6 = __rdtscp(&ui6);
			d1 = (i6-i5)/(state_size);
			printf("Final phase %2.2f cpb\n", (float)d1/(16));
			d2 = (i6-i1)/(state_size);
			printf("Total %2.2f cpb\n", (float)d2/(16));
#endif
#ifdef KAT
	fprintf(fp,"Tag: ");
	for(unsigned i=0; i<outlen; ++i)
		fprintf(fp,"%2.2x ",((unsigned char*)out)[i]);
	fprintf(fp,"\n");
	fclose(fp);
#endif

	delete[] state;
	return 0;
}


int PHS_internal(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, 
	uint32_t t_cost, size_t m_cost, uint32_t thread_n=1)
{
	return ArgonFast64(out, outlen, in, inlen, salt, saltlen, NULL, 0, t_cost, m_cost, thread_n);
}

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, 
	unsigned int t_cost, unsigned int m_cost)
{
	return ArgonFast64(out, outlen, in, inlen, salt, saltlen, NULL, 0, t_cost, m_cost, 1);
}

#ifdef ARGON_TEST
void GenKat(unsigned outlen)
{
	unsigned char out[32];
	unsigned char zero_array[256];
	memset(zero_array,0,256);
	unsigned t_cost = 3;
	unsigned m_cost = 2;
#ifdef KAT
	remove("kat-opt.log");
#endif
	for(unsigned p_len=0; p_len<=256; p_len+=32)
	{
		for(unsigned s_len=8; s_len<=32; s_len+=8)
		{
#ifdef _MEASURE
			uint64_t  i2,i3,d2;
			uint32_t ui2,ui3;
#endif
	

			outlen = s_len;
#ifdef _MEASURE
			clock_t start = clock();
			i2 = __rdtscp(&ui2);
#endif
			
			PHS_internal(out,outlen,sbox,p_len,subkeys[5],s_len,t_cost,m_cost);
			
#ifdef _MEASURE
			i3 = __rdtscp(&ui3);
			clock_t finish = clock();

			d2 = (i3-i2)/(m_cost);
			float mcycles = (float)(i3-i2)/(1<<20);
			printf("Argon:  %d iterations %2.2f cpb %2.2f Mcycles\n", t_cost, (float)d2/1000,mcycles);

			printf("Tag: ");
			for(unsigned i=0; i<outlen; ++i)
				printf("%2.2x ",((unsigned char*)out)[i]);
			printf("\n");
			
			float run_time = ((float)finish-start)/(CLOCKS_PER_SEC);
			printf("%2.4f seconds\n", run_time);
			#endif
		}
	}
}

void Benchmark()  //Benchmarks Argon with salt length 16, password length 128, tcost 3, and different threads and mcost
{
	unsigned char out[32];
	int i = 0;
	size_t outlen = 16;
	uint32_t t_cost = 3;
	size_t inlen = 128;
	size_t saltlen = 16;

	for (size_t m_cost = (size_t)1 << 10; m_cost <= (size_t)1 << 22; m_cost*=2)
	{
		for (uint32_t thread_n = 1; thread_n <= 16; thread_n++)
		{

#ifdef _MEASURE
			uint64_t  i2, i3, d2;
			uint32_t ui2, ui3;
			clock_t start = clock();
			i2 = __rdtscp(&ui2);
#endif

			ArgonFast64(out, outlen, sbox, inlen, subkeys[5], saltlen, NULL, 0, t_cost, m_cost, thread_n);

#ifdef _MEASURE
			i3 = __rdtscp(&ui3);
			clock_t finish = clock();
			d2 = (i3 - i2) / (m_cost);
			float mcycles = (float)(i3 - i2) / (1 << 20);
			printf("Argon:  %2.2f cpb %2.2f Mcycles ", (float)d2 / 1000, mcycles);
			float run_time = ((float)finish - start) / (CLOCKS_PER_SEC);
			printf("%2.4f seconds\n\n", run_time);
#endif
		}
	}
}

void Run(void *out, size_t outlen, size_t inlen, size_t saltlen,
	uint32_t t_cost, size_t m_cost, uint32_t thread_n)
{
	#ifdef _MEASURE
		uint64_t  i2, i3, d2;
		uint32_t ui2, ui3;
		clock_t start = clock();
		i2 = __rdtscp(&ui2);
	#endif

		PHS_internal(out, outlen, sbox, inlen, subkeys[5], saltlen, t_cost, m_cost, thread_n);

	#ifdef _MEASURE
		i3 = __rdtscp(&ui3);
		clock_t finish = clock();
		d2 = (i3 - i2) / (m_cost);
		float mcycles = (float)(i3 - i2) / (1 << 20);
		printf("Argon:  %2.2f cpb %2.2f Mcycles ", (float)d2 / 1000, mcycles);
		float run_time = ((float)finish - start) / (CLOCKS_PER_SEC);
		printf("%2.4f seconds\n", run_time);
	#endif

}

int main(int argc, char* argv[])
{	
	unsigned char out[32];
	int i=0;
	size_t outlen = 32;
	size_t m_cost=1<<18;
	uint32_t t_cost=3;
	size_t p_len = 16;
	unsigned thread_n =4;
	size_t s_len = 16;

	if(argc==1)
	{
		printf("-taglength <Tag Length 0..31> -logmcost <Base 2 logarithm of m_cost 0..23> -tcost <t_cost 0..2^24> -pwdlen <Password length> -saltlen <Salt Length> -threads <Number of threads 0..31>\n");
		printf("No arguments given. Argon is called with default parameters t_cost =3 and m_cost=2. Passwords are substrings of the AES S-box lookup table.\n");
		GenKat(32);
	}

	else
		{for (int i=1; i< argc; i++) 
		 {
			 if(strcmp(argv[i],"-taglength")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 outlen = atoi(argv[i])%32;
					 continue;
				 }
			 }
			 if(strcmp(argv[i],"-logmcost")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 m_cost = (size_t)1<<(atoi(argv[i])%24);
					 continue;
				 }
			 }
			 if(strcmp(argv[i],"-tcost")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 t_cost = atoi(argv[i])&0xffffff;
					 continue;
				 }
			 }
			 if(strcmp(argv[i],"-pwdlen")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 p_len = atoi(argv[i])%160;
					 continue;
				 }
			 }
			 if(strcmp(argv[i],"-saltlen")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 s_len = atoi(argv[i])%32;
					 continue;
				 }
			 }
			 if(strcmp(argv[i],"-threads")==0)
			 {
				 if(i<argc-1)
				 {
					 i++;
					 thread_n = atoi(argv[i])%32;
					 continue;
				 }
			 }
			 if (strcmp(argv[i], "-benchmark") == 0)
			 {
				 Benchmark();
				 return 0;
			 }
		 }//end of for
	Run(out, outlen, p_len, s_len, t_cost, m_cost, thread_n);
	}//end of else
	return 0;
}
#endif
