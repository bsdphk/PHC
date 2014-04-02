//# Algorithm Name: MCSSHA-8
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 15.02.2014 

#ifndef HEADER_MCSSHA8_MACROS_H
#define HEADER_MCSSHA8_MACROS_H




#define CHECK_HASH_LEN \
	    if(c->SRbyteLen != 128 && c->SRbyteLen != 64 && c->SRbyteLen != 32 && c->SRbyteLen != 16 && c->SRbyteLen != 8)return BAD_HASHBITLEN;


#define ADD_POINTS \
             x1++; \
             x2++; \
             x3++; \
             x4++;

#define MOD_POINTS \
	        if(x1 == SRLen)x1 = 0;  \
	        if(x2 == SRLen)x2 = 0;  \
	        if(x3 == SRLen)x3 = 0;  \
	        if(x4 == SRLen)x4 = 0;  

#define INCREASE_POINTS \
	         ADD_POINTS \
			 MOD_POINTS

#define INCREASE_POINTS_2N \
        x1 = (x1 + 1) & SRLen_1; \
        x2 = (x2 + 1) & SRLen_1; \
        x3 = (x3 + 1) & SRLen_1; \
        x4 = (x4 + 1) & SRLen_1; 

#define INPUT_BYTE \
	if(bits == 0)empty = data[i]; \
	 else { empty = last ^ (data[i]>>bits);  \
	        last = data[i]<<(8-bits);}  

#define INPUT_BYTE1 \
	if(bits == 0)empty = data1[i]; \
	 else { empty = last ^ (data1[i]>>bits);  \
	        last = data1[i]<<(8-bits);}  

#define INPUT_BYTE2 \
	if(bits == 0)empty = data2[i]; \
	 else { empty = last ^ (data2[i]>>bits);  \
	        last = data2[i]<<(8-bits);}  


#define SUBSTITUTION \
     S[(unsigned char)(c->data[x1] - c->data[x2] - c->data[x3] + c->data[x4])]


#define DELAY  \
     empty = SUBSTITUTION; \
	 INCREASE_POINTS  \
	 c->data[x4] = empty; \
     empty = SUBSTITUTION; \
	 INCREASE_POINTS  \
	 c->data[x4] = empty; \
     empty = SUBSTITUTION; \
	 INCREASE_POINTS  \
	 c->data[x4] = empty;  

#define SKIP_POINT  \
				if(j1 > 0)j1--;  \
			else j1 = (BitSequence)c->SRbyteLen - 1; 




#endif	
