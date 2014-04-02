//# Algorithm Name: MCSSHA-8
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 17.02.2014 

#ifndef HEADER_MCSSHA8_H
#define HEADER_MCSSHA8_H


typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

#define MCSSHA8_LBLOCK       	128

typedef struct state_st
	{
	DataLength hashbitlen;
	DataLength SRbyteLen;
	BitSequence x[6];
	BitSequence data[MCSSHA8_LBLOCK];
	} hashState;


HashReturn Init(hashState *c,DataLength hashbitlen);
HashReturn Update(hashState *c, const BitSequence *data, DataLength databitlen);
HashReturn Final(hashState *c, BitSequence *md);
HashReturn Hash(DataLength hashbitlen,
					   const BitSequence *data,
					   DataLength databitlen,
					   BitSequence *hashval);

#endif	
