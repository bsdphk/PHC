/**
 * Header file for the Lyra2 Password Hashing Scheme (PHS). Experimental CUDA implementation.
 * 
 * Note: Implemented without shared memory optimizations.
 * 
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
 * 
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

