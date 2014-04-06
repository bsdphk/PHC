// PHC submission:  POMELO
// Designed by:     Hongjun Wu
//                  Email: wuhongjun@gmail.com
// This code was written by Hongjun Wu on March 31, 2014.
// This code was corrected by Hongjun Wu on April 5, 2014
// The corrections are: the loading of salt into the state
//                      the shifting constants in function G and H.
//                      the order of operations in function F


// t_cost is a non-negative integer not larger than 20;
// m_cost is a non-negative integer not larger than 18;
// it is recommended that:  8 <= t_cost + m_cost <= 20;
// one may use the parameters: m_cost = 12; t_cost = 1;

#include <stdlib.h>
#include <string.h>

#define F(S,i)  {         \
    i1 = (i - 1)  & mask; \
    i2 = (i - 3)  & mask; \
    i3 = (i - 17) & mask; \
    i4 = (i - 41) & mask; \
    S[i] += ((S[i1] ^ S[i2]) + S[i3]) ^ S[i4]; \
    S[i] = (S[i] << 17) ^ (S[i] >> 47);        \
}

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
    unsigned long long i, j, temp;
    unsigned long long i1,i2,i3,i4;
    unsigned long long *S;
    unsigned long long mask, index;
    unsigned long long state_size;

    //Step 1:  Initialize the state S.
    state_size = 8192 << m_cost;
    S = (unsigned long long *)calloc(state_size, 1);

    mask = state_size/8 - 1;     //mask is used for modulation: modulo size_size/8

    //Step 2:  Load the password, salt, input/output sizes into the state S
    // load password into S
    for (i = 0; i < inlen; i++)   ((unsigned char*)S)[i] = ((unsigned char*)in)[i];
    for (i = inlen; i < 128; i++) ((unsigned char*)S)[i] = 0;
    // load salt into S
    for (i = 0; i < saltlen; i++)       ((unsigned char*)S)[i+128] = ((unsigned char*)salt)[i];
    for (i = 128+saltlen; i < 160; i++) ((unsigned char*)S)[i] = 0;

    ((unsigned char*)S)[160] = inlen;   // load password length (in bytes) into S;
    ((unsigned char*)S)[161] = saltlen; // load salt length (in bytes) into S;
    ((unsigned char*)S)[162] = outlen;  // load output length (in bytes into S)

    //Step 3: Expand the data into the whole state.
    for (i = 41; i < state_size/8; i++)
    {
        F(S,i);
    }

    //Step 4: update the state using F and G
    //       (involving deterministic random memory accesses)
    temp = 1;
    for (j = 0; j < (1 << t_cost); j++)
    {
       for (i = 0; i < state_size/8; i++)
       {
           F(S,i);

           // function G(S, i, j)
           if ( (i & 3) == 3 )
           {
               index     = (temp + (temp >> 32)) & mask;
               S[i]     ^= S[index] << 1;
               S[index] ^= S[i] << 3;
           }

           temp = temp + (temp << 2);   // temp = temp*5;
       }
    }

    // Step 5: update the state using F
    for (i = 0; i < state_size/8; i++)
    {
        F(S,i);
    }

    //Step 6: update the state using F and H
    //       (involving password-dependent random memory accesses)
    for (j = 0; j < (1 << t_cost); j++)
    {
       for (i = 0; i < state_size/8; i++)
       {
           F(S,i);

           // function H(S, i)
           if ( (i & 3) == 3 )
           {
               i1 = (i - 1)  & mask;
               index = S[i1] & mask;
               S[i]     ^= S[index] << 1;
               S[index] ^= S[i] << 3;
           }
       }
    }

    // Step 7: update the state using F
    for (i = 0; i < state_size/8; i++)
    {
        F(S,i);
    }

    //Step 8: generate the output
    if (outlen > 128)   // the maximum output size is 128 bytes; otherwise, no output.
    {
        memset(S, 0, state_size); // clear the memory
        free(S);                  // free the memory
        return 1;     // there is no output if the output size is more than 128 bytes.
    }

    memcpy(out, ((unsigned char*)S)+state_size-outlen, outlen);
    memset(S, 0, state_size);  //clear the memory
    free(S);                   // free the memory

    return 0;
}
