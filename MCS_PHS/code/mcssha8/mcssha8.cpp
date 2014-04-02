//# Algorithm Name: MCSSHA-8
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 17.02.2014 

#include <stdio.h>
#include <memory.h>
#include "mcssha8.h"
#include "mcssha8_macros.h"

//#define DEBUG_MODE

// logariphmic substitution
static BitSequence S[256]={
	0x30, 0x60, 0x67, 0xB5, 0x43, 0xEA, 0x93, 0x25,	0x48, 0x0D, 0x18, 0x6F, 0x28, 0x7A, 0xFE, 0xB6,
	0xD5, 0x9C, 0x23, 0x86, 0x52, 0x42, 0xF7, 0xFD,	0xF6, 0x9B, 0xEE, 0x99, 0x91, 0xBC, 0x2A, 0x63,
	0xA1, 0xA0, 0x57, 0x3C, 0x39, 0xD2, 0xEC, 0x71,	0x45, 0xCB, 0x41, 0xDC, 0x0B, 0x5B, 0xC2, 0x36,
	0x01, 0x55, 0x7D, 0xFB, 0xED, 0x83, 0x8F, 0x31,	0xC0, 0x4C, 0x08, 0xE3, 0x9D, 0xC1, 0xD3, 0xE9,
	0xB8, 0xBD, 0xAE, 0x0F, 0xE7, 0x70, 0x5A, 0xEB,	0x4D, 0x29, 0xF9, 0xA9, 0x3D, 0x26, 0x46, 0x06,
	0xD0, 0x50, 0xA5, 0xBE, 0x66, 0x90, 0xF4, 0x20,	0xE4, 0x33, 0x27, 0xE2, 0xAB, 0xEF, 0x68, 0x54,
	0x37, 0x6A, 0xDB, 0xBB, 0xD8, 0x7B, 0x69, 0xC4,	0xF2, 0xBF, 0x85, 0xC7, 0xA6, 0xB4, 0x9A, 0xDD,
	0x72, 0x34, 0xE8, 0xFC, 0xD6, 0x21, 0x98, 0x96,	0x32, 0xCA, 0x49, 0xB3, 0xF3, 0x97, 0x8E, 0x2F,
	0x00, 0xB0, 0x10, 0x1A, 0x77, 0x38, 0xCF, 0x51,	0xBA, 0x1F, 0x22, 0xAC, 0x62, 0x89, 0x76, 0xC3,
	0x02, 0x6E, 0x2C, 0x47, 0x3A, 0x5C, 0x1B, 0x56,	0x8A, 0x5D, 0x03, 0x16, 0x74, 0x58, 0x79, 0x09,
	0xD7, 0xF5, 0x0A, 0x92, 0x4F, 0x87, 0xCD, 0xDA,	0x8C, 0xC9, 0x9E, 0x3B, 0x12, 0x6B, 0x53, 0xFF,
	0x80, 0xB7, 0xF8, 0xD9, 0xF1, 0x5E, 0xAF, 0xE0,	0x05, 0xA4, 0x14, 0x2B, 0xA3, 0xCC, 0x6C, 0x7C,
	0x78, 0xAA, 0x95, 0x84, 0x61, 0xA8, 0xCE, 0x13,	0x88, 0xFA, 0x59, 0x4E, 0xB9, 0xC8, 0x4B, 0x24,
	0xD1, 0x07, 0x94, 0x2E, 0xDF, 0xB1, 0x17, 0xA2,	0x1D, 0x4A, 0xC6, 0xAD, 0x15, 0x19, 0x35, 0x7F,
	0x81, 0x44, 0x0C, 0x9F, 0x75, 0x7E, 0xD4, 0x82,	0xDE, 0xE6, 0xE1, 0x2D, 0x3E, 0x73, 0x11, 0x8B,
	0xC5, 0xA7, 0xF0, 0x6D, 0x1C, 0x64, 0x0E, 0x04,	0x40, 0x1E, 0x8D, 0xE5, 0x3F, 0xB2, 0x65, 0x5F,
	};

// Delay is constant for MCSSHA-8
// Reserved. Not used.
static BitSequence delay = 3;

// Hash Init
// Prepare hashState structure
// c->hashbitlen - remember hashbitlen for final hash computation
// c->SRbyteLen - calculate SR length in bytes for pre-hach and final hash computation
// Initialize SR for pre-hash computation
// Prepare two bytes for remain bits
// Total size hashState structure = 152 bytes
HashReturn Init(hashState *c,DataLength hashbitlen)
	{
		BitSequence i;
		if(c == NULL)return FAIL;
		if((hashbitlen & 0x7) != 0)return BAD_HASHBITLEN;
		c->SRbyteLen = (hashbitlen>>3);

		if(c->SRbyteLen > 32 && c->SRbyteLen <= 64)c->SRbyteLen = 128;
		else if(c->SRbyteLen > 16 && c->SRbyteLen <= 32)c->SRbyteLen = 64;
		else if(c->SRbyteLen > 8 && c->SRbyteLen <= 16)c->SRbyteLen = 32;
		else if(c->SRbyteLen > 4 && c->SRbyteLen <= 8)c->SRbyteLen = 16;
		else if(c->SRbyteLen ==  4)c->SRbyteLen = 8;
		else return BAD_HASHBITLEN;

		c->hashbitlen = hashbitlen;
		c->x[0] = 0;
		c->x[1] = 1;
		c->x[2] = (BitSequence)(c->SRbyteLen - 4);
		c->x[3] = (BitSequence)(c->SRbyteLen - 1);
	    for( i = 0; i < c->SRbyteLen; i++)c->data[i] = i;
// Two parameters for DataLength != 8*k bits
// bits - number of the last bits, i.e. DataLength - 8*k
		c->x[4] = 0;
// last - last bits value
		c->x[5] = 0;

		return(SUCCESS);
	}

//-------------------------------------------------------------------

// Pre-hash computation.

HashReturn Update(hashState *c, const BitSequence *data, DataLength databitlen)
	{

		DataLength len = databitlen>>3;
		register unsigned long x1,x2,x3,x4,SRLen,i,len1;
		BitSequence empty,bits,last,SRLen_1;

// Control tests
		if((c == NULL) || (data == NULL && databitlen != 0)) return FAIL;
        if((data == NULL) && (databitlen == 0))return(SUCCESS);
        CHECK_HASH_LEN

        if((data == NULL) && (databitlen == 0))return SUCCESS;
		if((data == NULL) && (databitlen != 0))return FAIL;
// For use fast register memory
		x1 = c->x[0];
		x2 = c->x[1];
		x3 = c->x[2];
		x4 = c->x[3];
		bits = c->x[4];
		last = c->x[5];
		SRLen = (unsigned long)c->SRbyteLen;
		SRLen_1 = (BitSequence)c->SRbyteLen - 1;



		i = 0;
		len1 = (unsigned long)((databitlen + bits)>>3);
		while(i < len1)
		{
 			INPUT_BYTE
			empty += SUBSTITUTION;
            INCREASE_POINTS_2N
			c->data[x4] = empty;
			DELAY
			i++; 
		}

		if(bits == 0)
		{
// Prepare remain bits and remain bits length
		   c->x[4] = (BitSequence)(databitlen  - (len<<3));
		   if(c->x[4] != 0)c->x[5] = ((data[i]<<(8-c->x[4]))>>(8-c->x[4]));
		}
		else
		{
// Calculate remain bits and remain bits length for next step
		   c->x[4] = (BitSequence)(databitlen + bits - (i<<3));
		   if(i != 0)c->x[5] = (last>>(8-c->x[4]))<<(8-c->x[4]);
		   else c->x[5] = ((last ^ (data[i]>>bits))>>(8-c->x[4]))<<(8-c->x[4]);
		}


// Restore hash structure
		c->x[0]=(BitSequence)x1;
		c->x[1]=(BitSequence)x2;
		c->x[2]=(BitSequence)x3;
		c->x[3]=(BitSequence)x4;

		return(SUCCESS);

	}


//---------------------------------------------------------------------------

// Final hash computation
HashReturn Final(hashState *c, BitSequence *md)
{


		register unsigned long x1,x2,x3,x4,SRLen,i;
		BitSequence empty,bits,last;
		BitSequence data1[65],data2[65];
		BitSequence i1,j1,i2;

		if(c == NULL || md == NULL)return FAIL;
		CHECK_HASH_LEN
		bits = c->x[4];
		last = c->x[5];

		i1 = 0;
		i2 = 0;
		j1 = c->x[3]; 
	    
        SRLen = (unsigned long)(c->hashbitlen>>3);
		while( i2 < SRLen )
		{
			if(i1 < SRLen)data1[i1] = c->data[j1];
			i1++;
			SKIP_POINT
			if(i1 < SRLen)data1[i1] = c->data[j1];
			i1++;
			SKIP_POINT
			if(i2 < SRLen)data2[i2] = c->data[j1];
			i2++;
			SKIP_POINT
			if(i2 < SRLen)data2[i2] = c->data[j1];
			i2++;
			SKIP_POINT
		}
		data1[SRLen] = (BitSequence)SRLen;
		data2[SRLen] = (BitSequence)SRLen;
		
		for(i = 0; i < SRLen; i ++)c->data[i] = (BitSequence)i;

		x1 = 0;
		x2 = 1;
		x4 = SRLen - 1;
		if(SRLen > 6)
			x3 = SRLen - 4;
		else
			x3 = 2;

		i = 0;
		while(i < SRLen + 1)
		{
			INPUT_BYTE1  
			empty += SUBSTITUTION;
            INCREASE_POINTS
			c->data[x4] = empty;
			i++; 
		}

		memcpy(md,c->data,SRLen);

		for(i = 0; i < SRLen; i ++)c->data[i] = (BitSequence)i;

		x1 = 0;
		x2 = 1;
		x4 = SRLen - 1;
		if(SRLen > 6)
			x3 = SRLen - 4;
		else
			x3 = 2;

		i = 0;
		while(i < SRLen + 1)
		{
            if(i == SRLen - 1)
				i = i;
			INPUT_BYTE2  
			empty += SUBSTITUTION;
            INCREASE_POINTS
			c->data[x4] = empty;
			i++; 
		}
		for(i = 0; i < SRLen; i ++)md[i] ^= c->data[i];

return (SUCCESS);
}


//------------------------------------------------------------------



HashReturn Hash(DataLength hashbitlen,
				const BitSequence *data,
				DataLength databitlen,
				BitSequence *hashval)
{
	  HashReturn ret;
	  hashState c;
	  ret = Init(&c,hashbitlen);
	  if(ret != SUCCESS)return(ret);
	  ret = Update(&c,data,databitlen);
	  if(ret != SUCCESS)return(ret);
	  return(Final(&c,hashval));
}

//------------------------------------------------------------------


