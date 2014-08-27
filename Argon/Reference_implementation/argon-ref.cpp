#include "stdio.h"

#include "string.h"
#include <algorithm>    
#include "time.h"
using namespace std;

#define MAX_OUTLEN 32
#define MIN_MEMORY 1
#define MAX_MEMORY (1<<31)
#define MIN_TIME 1
#define LENGTH_SIZE 4
#define MIN_PASSWORD 0
#define MAX_PASSWORD 256
#define MAX_SALT  32
#define MAX_SECRET 16
#define INPUT_SIZE (INPUT_BLOCKS*12)
#define INPUT_BLOCKS 32
#define CACHE_SIZE 128
#define BATCH_SIZE 16
#define GROUP_SIZE 32

#define AES_ROUNDS 5

#define u32 unsigned __int32
#define u64 unsigned long long int



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

u64 subkeys64[11][2]=
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

struct int128{
	u64 i0,i1;
	int128(u64 y0=0, u64 y1=0){i0 = y0; i1 = y1;};
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

unsigned char mul[256][256]; //GF(256) multiplication table, initialized in Init().

void AES_Round(unsigned char* state, unsigned char* subkey)  //SubBytes-ShiftRows-MixColumns-AddRoundKey
{
	unsigned char tmp[4][4];

	for(unsigned i=0; i<4; ++i)
	{
		for(unsigned j=0; j<4; ++j)
			tmp[j][i] = state[4*i+j];//AES state conversion
	}
	for(unsigned i=0; i<4; ++i)//Columnwise loop
	 {
	 	state[4*i] = mul[sbox[tmp[0][i]]][2] ^ mul[sbox[tmp[3][(i+3)%4]]][1] ^
						mul[sbox[tmp[2][(i+2)%4]]][1] ^ mul[sbox[tmp[1][(i+1)%4]]][3];
		state[4*i+1] = mul[sbox[tmp[1][(i+1)%4]]][2] ^ mul[sbox[tmp[0][i]]][1] ^
					mul[sbox[tmp[3][(i+3)%4]]][1] ^ mul[sbox[tmp[2][(i+2)%4]]][3];
		state[4*i+2] = mul[sbox[tmp[2][(i+2)%4]]][2] ^ mul[sbox[tmp[1][(i+1)%4]]][1] ^
					mul[sbox[tmp[0][i]]][1] ^ mul[sbox[tmp[3][(i+3)%4]]][3];
		state[4*i+3] = mul[sbox[tmp[3][(i+3)%4]]][2] ^ mul[sbox[tmp[2][(i+2)%4]]][1] ^
					mul[sbox[tmp[1][(i+1)%4]]][1] ^ mul[sbox[tmp[0][i]]][3];
	 }
	for(unsigned i=0; i<16; ++i)
		state[i] ^= subkey[i];

}

//GF(256) multiplication

unsigned char gmul_o(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char counter;
	unsigned char hi_bit_set;
	for(counter = 0; counter < 8; counter++) {
		if((b & 1) == 1) 
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set == 0x80) 
			a ^= 0x1b;		
		b >>= 1;
	}
	return p;
}

void Init()
{
	for(unsigned i=0; i<256; ++i)
		{
			for(unsigned j=0; j<256; ++j)
				mul[i][j] = gmul_o(i,j);
		}
}


void AES_reduced(int128 &input)
{
	unsigned char state[16];
	/*unsigned char subkeys[AES_ROUNDS+1][16];
	memset(subkeys,0,(AES_ROUNDS+1)*16);
	for(unsigned i=0; i<16; i+=4)
		for(unsigned j=0; j<AES_ROUNDS+1; ++j)
			subkeys[j][i]=j+1;*/
	for(unsigned i=0; i<8; ++i)
			state[i] = (input.i0>>(i*8))&0xff ^ subkeys[0][i];//AES state conversion
	for(unsigned i=0; i<8; ++i)
		state[i+8] = (input.i1>>(i*8))&0xff ^ subkeys[0][i+8];
	
	for(unsigned i=0; i<AES_ROUNDS;++i)
		AES_Round(state,subkeys[i+1]);
	input.i0 = *((u64*)state);
	input.i1 = *((u64*)(state+8));

}


void SubGroups(int128* state, unsigned width)
{
	for(unsigned i=0; i<width; i+= 32)
	{
		//Computing X_i:
		int128 X[16];
		X[0]=state[i+3] ^ state[i+7] ^ state[i+11] ^ state[i+15] ^ state[i+19] ^ state[i+23] ^ state[i+27] ^ state[i+31];
		X[1]=state[i+1] ^ state[i+5] ^ state[i+9] ^ state[i+13] ^ state[i+17] ^ state[i+21] ^ state[i+25] ^ state[i+29];
		X[2]=state[i+2] ^ state[i+6] ^ state[i+10] ^ state[i+14] ^ state[i+18] ^ state[i+22] ^ state[i+26] ^ state[i+30];
		X[3]=state[i+0] ^ state[i+4] ^ state[i+8] ^ state[i+12] ^ state[i+16] ^ state[i+20] ^ state[i+24] ^ state[i+28];
		X[4]=state[i+12] ^ state[i+13] ^ state[i+14] ^ state[i+15] ^ state[i+28] ^ state[i+29] ^ state[i+30] ^ state[i+31];
		X[5]=state[i+4] ^ state[i+5] ^ state[i+6] ^ state[i+7] ^ state[i+20] ^ state[i+21] ^ state[i+22] ^ state[i+23];
		X[6]=state[i+8] ^ state[i+9] ^ state[i+10] ^ state[i+11] ^ state[i+24] ^ state[i+25] ^ state[i+26] ^ state[i+27];
		X[7]=state[i+17] ^ state[i+19] ^ state[i+21] ^ state[i+23] ^ state[i+25] ^ state[i+27] ^ state[i+29] ^ state[i+31];
		X[8]=state[i+1] ^ state[i+3] ^ state[i+5] ^ state[i+7] ^ state[i+9] ^ state[i+11] ^ state[i+13] ^ state[i+15];
		X[9]=state[i+0] ^ state[i+2] ^ state[i+4] ^ state[i+6] ^ state[i+16] ^ state[i+18] ^ state[i+20] ^ state[i+22];
		X[10]=state[i+0] ^ state[i+2] ^ state[i+8] ^ state[i+10] ^ state[i+16] ^ state[i+18] ^ state[i+24] ^ state[i+26];
		X[11]=state[i+2] ^ state[i+6] ^ state[i+10] ^ state[i+14] ^ state[i+18] ^ state[i+22] ^ state[i+26] ^ state[i+30];
		X[12]=state[i+10] ^ state[i+11] ^ state[i+14] ^ state[i+15] ^ state[i+26] ^ state[i+27] ^ state[i+30] ^ state[i+31];
		X[13]=state[i+2] ^ state[i+3] ^ state[i+6] ^ state[i+7] ^ state[i+10] ^ state[i+11] ^ state[i+14] ^ state[i+15];
		X[14]=state[i+12] ^ state[i+13] ^ state[i+14] ^ state[i+15] ^ state[i+28] ^ state[i+29] ^ state[i+30] ^ state[i+31];
		X[15]=state[i+0] ^ state[i+1] ^ state[i+2] ^ state[i+3] ^ state[i+8] ^ state[i+9] ^ state[i+10] ^ state[i+11];
		
		

		for(unsigned j=0; j<16;++j)
		{
			AES_reduced(X[j]);//Computing F's
			state[i+2*j] ^= X[j]; //XORs
			state[i+2*j+1] ^= X[j];
			AES_reduced(state[i+2*j]);
			AES_reduced(state[i+2*j+1]);
		}
	}
}


void ShuffleSlices(int128* state, unsigned width)
{
	for(unsigned s=0; s<32; ++s) //Loop on slices
	{
		unsigned j=0;
		for(unsigned i=0; i<width/32; ++i)
		{
			//j <- j+ S[i]
			//Swap(S[i],S[j])
			unsigned index1 = i*32 + s; 
			int128 v1 = state[index1];
			j = (j+ (v1.i0&0xffffffff))%(width/32);
			unsigned index2 = j*32+s;
			swap(state[index1],state[index2]);
		}
	}
}




extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	Init();  //Initializing Galois field multiplication table.
	int128* state;  //Array A of blocks

	//0. Restricting parameters
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




	//1. Preparing input string I 
	unsigned char Input[INPUT_SIZE];
	memset(Input,0,INPUT_SIZE);
	//1.1 Password length
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i] = (inlen>>(8*i))&0xff;  //Little endian password length encoding
	}
	//1.2 Salt length
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+LENGTH_SIZE] = (saltlen>>(8*i))&0xff;  //Little endian salt length encoding
	}
	//1.3 Garlic length  -- equal to 0 in the default function
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+2*LENGTH_SIZE] =0;
	}
	//1.4 Iteration number
	for(unsigned i=0; i<LENGTH_SIZE; ++i)
	{
		Input[i+3*LENGTH_SIZE] =(t_cost>>(8*i))&0xff;
	}
	//1.5 Memory parameter
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
	//1.9 Secret is empty
	//1.10 Padding
	for(unsigned i=6*LENGTH_SIZE+inlen+saltlen; i<INPUT_SIZE; ++i)
		Input[i] = 0;



	//2. Filling blocks
	unsigned state_size = m_cost*64;
	state = new int128[state_size];
	if(state==NULL)
		return 1;
	
	for(unsigned i=0; i<state_size; ++i)
	{
		//Input part
		unsigned input_block_index = 12*(i%INPUT_BLOCKS); //Position where we take the input block
		state[i].i0=0;
		for(unsigned j=0; j<8; ++j)
			state[i].i0 ^= ((u64)Input[input_block_index+j])<<(8*j);
		state[i].i1=0;
		for(unsigned j=0; j<4; ++j)
			state[i].i1 ^= ((u64)Input[input_block_index+8+j])<<(8*j);
		//Counter
		state[i].i1 ^= ((u64)i)<<(32);
	}
	memset(Input,0,INPUT_SIZE);

	//3. Initial transformation
	for(unsigned i=0; i<state_size; ++i)
	{
		AES_reduced(state[i]);
	}

	
	//4. Rounds: 
	for(unsigned l=0; l <t_cost; ++l)
	{
		SubGroups(state,state_size);

		ShuffleSlices(state,state_size);

	}

	//5.Finalization
	SubGroups(state,state_size);



	int128 a1(0,0);
	int128 a2(0,0);
	for(unsigned i=0; i< state_size/2; ++i)
	{
		a1 ^= state[i];
		a2 ^= state[i+state_size/2];
		state[i] = int128(0,0);
		state[i+state_size/2] = int128(0,0);
	}
	if(outlen<=16)
	{
		int128 tag=a1^a2;
		AES_reduced(tag);
		AES_reduced(tag);
		AES_reduced(tag);
		AES_reduced(tag);
		tag ^= a1^a2;
		for(unsigned i=0; i<outlen; ++i)
			((unsigned char*)out)[i] = tag[i];
	}
	else
	{
		int128 tag1=a1;
		AES_reduced(tag1);
		AES_reduced(tag1);
		AES_reduced(tag1);
		AES_reduced(tag1);
		tag1 ^= a1;
		for(unsigned i=0; i<16; ++i)
			((unsigned char*)out)[i] = tag1[i];
		int128 tag2=a2;
		AES_reduced(tag2);
		AES_reduced(tag2);
		AES_reduced(tag2);
		AES_reduced(tag2);
		tag2 ^= a2;
		for(unsigned i=16; i<outlen; ++i)
			((unsigned char*)out)[i] = tag2[i-16];
	}
	

	delete state;
	return 0;
}

#ifdef ARGON_TEST
void GenKat(unsigned outlen)
{
	unsigned char out[32];
	unsigned char zero_array[256];
	memset(zero_array,0,256);
	unsigned t_cost = 3;
	unsigned m_cost = 2;
	remove("out.log");
	FILE* fp=fopen("kat.log","w+");
	for(unsigned p_len=0; p_len<=256; p_len+=16)
	{
		for(unsigned s_len=8; s_len<=32; s_len+=8)
		{	
			outlen = s_len;
			PHS(out,outlen,sbox,p_len,subkeys[5],s_len,t_cost,m_cost);
			fprintf(fp,"Tag: ");
			for(unsigned i=0; i<outlen; ++i)
				fprintf(fp,"%2.2x ",((unsigned char*)out)[i]);
			fprintf(fp,"\n");
		}
	}
	fclose(fp);
}


int main(int argc, char* argv[])
{	
	GenKat(32);
	return 0;
}
#endif
