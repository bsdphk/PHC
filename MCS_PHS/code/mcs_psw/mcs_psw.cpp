//# Algorithm Name: MCS_PSW
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 12.02.2014 

#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include "mcs_psw.h"
#include "../mcssha8/mcssha8.h"

// MCS password hashing scheme (MCS_PHS)
extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
     int ret = 0;
     uint32_t dwErr = 0;
     uint8_t tmp[256]; //temprorary memory for MCS_PHS
     uint8_t hash[64] = {0};
     unsigned int i = 0;
     unsigned int len = 0;
     unsigned int mcost = 256;
     do
     {
//Parameters control
         if(
             out == NULL  ||
             outlen == 0  ||
             ( in == NULL && inlen != 0 )  || 
             inlen == 0   ||
             salt == 0    ||
             saltlen == 0 ||
             inlen + saltlen > 256 ||
             outlen > 64
             ){
                 dwErr = 1;
                 break;
         }

         if(m_cost != 0)
             mcost = m_cost;

         if(mcost < saltlen + inlen + 2)
         {
                 dwErr = 1;
                 break;
         }

// Preparing temprorary memory

         tmp[0] = inlen;  // Password length (to protect from password's length attack)

         if(inlen != 0)memcpy(tmp + 1,in,inlen); // add password

         tmp[inlen + 1] = saltlen;

         memcpy(tmp + inlen + 2 ,salt,saltlen); // add salt
         
         for(i = saltlen + inlen + 2; i < mcost; i++)tmp[i] = i; // add auxiliary bytes


// First hashing using MCSSHA-8. Hash length = 64 bytes 
         if(Hash(512,tmp,mcost<<3,hash))
         {
                dwErr = 2;
                break;
         }
// Main hash cycle. Each step reduces the length of the hash on 1 from 64 to 32 bytes.
         for( i = 63; i >= outlen; i--)
         {
             if(Hash(i<<3,hash,(i+1)<<3,hash))
             {
                    dwErr = 2;
                    break;
             }
         }
         if(i >= outlen)break;

// If t_cost != 0 perform additional cycle.
         if(t_cost)
         {
             for(i = 0; i < t_cost; i++)
             {
                 if(Hash(outlen<<3,hash,outlen<<3,hash))
                 {
                        dwErr = 2;
                        break;
                 }
             }
             if(i < t_cost)break;
         }

// Perform final computation for protect against attack in 5.1 (PBKDF1) from Frances F. Yao and Yiqun Lisa Yin "Design and Analysis of Password-Based Key Derivation Functions"

        if(outlen != 64)
        {
            if(Hash(512,hash,outlen<<3,hash) || Hash(outlen<<3,hash,512,hash))
            {
                dwErr = 2;
                break;
            }
        }
        else
        {
            for(i = 0; i < 64; i++)hash[i] += (uint8_t)i;
            if(Hash(512,hash,512,hash))
            {
                dwErr = 2;
                break;
            }

        }

// Final hash for password
         memcpy(out,hash,outlen);

     }while(0);

     if(dwErr != 0)ret = -1;

     return ret;
}
