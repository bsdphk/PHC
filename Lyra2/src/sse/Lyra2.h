/**
 * Header file for the Lyra2 Password Hashing Scheme (PHS). SSE-oriented implementation.
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

#define BLOCK_LEN_INT64 12                               //Block length: 768 bits (=96 bytes, =12 uint64_t)
#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)           //Block length, in bytes

#define BLOCK_LEN_INT128 6                              //Block lenght: 512 bits (=64 bytes, =4 __m128i)
#define BLOCK_LEN_BYTES_SSE (BLOCK_LEN_INT128 * 16)           //Block lenght, in bytes

#ifndef N_COLS
#define N_COLS 64                                       //Number of columns in the memory matrix: fixed to 64
#endif

int LYRA2(unsigned char *K, int kLen, const unsigned char *pwd, int pwdlen, const unsigned char *salt, int saltlen, int timeCost, int nRows, int nCols);

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#endif /* LYRA2_H_ */
