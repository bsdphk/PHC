/*
   
        Implementation of Lyra2.
  
   LYRA2 reference source code package - experimental CUDA implementation - <http://www.lyra-kdf.net/>

   Written in 2014 by Leonardo de Campos Almeida <lalmeida@larc.usp.br>
   Edited in 2014 by Paulo C. F. Santos <pcarlos@ime.usp.br>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   
   Note:
   Implemented without shared memory optimizations.
*/
#ifndef LYRA2_H_
#define LYRA2_H_

typedef unsigned char byte ;

#define SALT_LEN_INT64 2                                //Salts must have 128 bits (=16 bytes, =2 uint64_t)
#define SALT_LEN_BYTES (SALT_LEN_INT64 * 8)             //Salt length, in bytes

#define BLOCK_LEN_INT64 12                               //Block lenght: 768 bits (=96 bytes, =8 uint64_t)
#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)           //Block lenght, in bytes

#ifndef N_COLS
#define N_COLS 64                                       //Number of columns in the memory matrix: fixed to 64
#endif

#define ROW_LEN_INT64 (BLOCK_LEN_INT64 * N_COLS)        //Total length of a row: 64 blocks, or 512 uint64_t
#define ROW_LEN_BYTES (ROW_LEN_INT64 * 8)               //Number of bytes per row: 512 * 8


int LYRA2(unsigned char *K, int kLen, const unsigned char *pwd, int pwdlen, const unsigned char *salt, int saltlen, int timeCost, int nRows, int nCols);

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#endif /* LYRA2_H_ */

