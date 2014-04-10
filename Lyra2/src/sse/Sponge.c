/**
 * A simple implementation of Blake2b's internal permutation 
 * in the form of a sponge. SSE-optimized implementation.
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
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <immintrin.h>
#include "blake2b-round.h"
#include "Sponge.h"
#include "Lyra2.h"


/**
 * Initializes the Sponge State. The first 512 bits are set to zeros and the remainder 
 * receive Blake2b's IV as per Blake2b's specification. <b>Note:</b> Even though sponges
 * typically have their internal state initialized with zeros, Blake2b's G function
 * has a fixed point: if the internal state and message are both filled with zeros. the 
 * resulting permutation will always be a block filled with zeros; this happens because 
 * Blake2b does not use the constants originally employed in Blake2 inside its G function, 
 * relying on the IV for avoiding possible fixed points.
 * 
 * @param state         The 1024-bit array to be initialized
 */
void inline initStateSSE(__m128i state[/*8*/]){
    memset(state, 0, 64); //first 512 bis are zeros
    state[4] = _mm_load_si128((__m128i *) &blake2b_IV[0]);
    state[5] = _mm_load_si128((__m128i *) &blake2b_IV[2]);
    state[6] = _mm_load_si128((__m128i *) &blake2b_IV[4]);
    state[7] = _mm_load_si128((__m128i *) &blake2b_IV[6]);
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 * 
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
static inline void blake2bLyraSSE(__m128i *v){
    __m128i t0, t1;

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);
    ROUND(10);
    ROUND(11);
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
static inline void reducedBlake2bLyraSSE(__m128i *v){
    __m128i t0, t1;

    ROUND(0);    
}

/**
 * Performs a squeeze operation, using Blake2b's G function as the 
 * internal permutation
 * 
 * @param state      The current state of the sponge 
 * @param out        Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
void squeezeSSE(__m128i *state, byte *out, unsigned int len) {
    int fullBlocks = len / 64;
    byte *ptr = out;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        memcpy(ptr, state, BLOCK_LEN_BYTES);
        blake2bLyraSSE(state);

        ptr += BLOCK_LEN_BYTES;
    }
    memcpy(ptr, state, (len % 64));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed 
 */
void absorbBlockSSE(__m128i *state, const __m128i *in){
    state[0] = _mm_xor_si128(state[0], in[0]);
    state[1] = _mm_xor_si128(state[1], in[1]);
    state[2] = _mm_xor_si128(state[2], in[2]);
    state[3] = _mm_xor_si128(state[3], in[3]);
    state[4] = _mm_xor_si128(state[4], in[4]);
    state[5] = _mm_xor_si128(state[5], in[5]);

    //Applies the transformation f to the sponge's state
    blake2bLyraSSE(state);
}


void absorbPaddedSaltSSE(__m128i *state, const unsigned char *salt) {
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] = _mm_xor_si128(state[0], _mm_set_epi8(salt[15],salt[14],salt[13],salt[12],salt[11],salt[10],salt[9],salt[8],salt[7],salt[6],salt[5],salt[4],salt[3],salt[2],salt[1],salt[0]));
    state[1] = _mm_xor_si128(state[1], _mm_set_epi64x(0, 0x80));
    state[3] = _mm_xor_si128(state[3], _mm_set_epi64x(0x0100000000000000ULL, 0));
    blake2bLyraSSE(state);
}


void squeezeBlockSSE(__m128i* state, __m128i* block){
    memcpy(block, state, BLOCK_LEN_BYTES);
    blake2bLyraSSE(state);
}

/** 
 * Performs a squeeze operation for two rows in sequence, using 
 * reduced Blake2b's G function as the internal permutation
 * 
 * @param state     The current state of the sponge 
 * @param row       Row to receive the data squeezed
 * @param nCols     Number of Columns
 */
void reducedSqueezeRowSSE(__m128i* state, __m128i* row, int nCols) {
    int i;
    //M[row][col] = H.reduced_squeeze()    
    for (i = 0; i < nCols; i++) {
        row[0] = state[0];
        row[1] = state[1];
        row[2] = state[2];
        row[3] = state[3];
        row[4] = state[4];
        row[5] = state[5];
        row[6] = state[6];

        //Goes to next block (column) that will receive the squeezed data
        row += BLOCK_LEN_INT128;

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyraSSE(state);
    }
}

/**
 * Performs a duplex operation over "M[rowInOut] XOR M[rowIn]", writing the output "rand"
 * on M[rowOut] and making "M[rowInOut] =  M[rowInOut] XOR rotW(rand)", where rotW is a 64-bit 
 * rotation to the left.
 *
 * @param state          The current state of the sponge 
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 * @param nCols          Number of Columns
 *
 */
void reducedDuplexRowSetupSSE(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut, int nCols){
    __m128i* ptr64In = rowIn; 		//In Lyra2: pointer to prev
    __m128i* ptr64InOut = rowInOut; 	//In Lyra2: pointer to row*
    __m128i* ptr64Out = rowOut; 	//In Lyra2: pointer to row
    int i;

    for (i = 0; i < nCols; i++){
        //Absorbing "M[rowInOut] XOR M[rowIn]"
        state[0] = _mm_xor_si128(state[0], _mm_xor_si128(ptr64InOut[0], ptr64In[0]));
        state[1] = _mm_xor_si128(state[1], _mm_xor_si128(ptr64InOut[1], ptr64In[1]));
        state[2] = _mm_xor_si128(state[2], _mm_xor_si128(ptr64InOut[2], ptr64In[2]));
        state[3] = _mm_xor_si128(state[3], _mm_xor_si128(ptr64InOut[3], ptr64In[3]));
	state[4] = _mm_xor_si128(state[4], _mm_xor_si128(ptr64InOut[4], ptr64In[4]));
        state[5] = _mm_xor_si128(state[5], _mm_xor_si128(ptr64InOut[5], ptr64In[5]));

        
        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyraSSE(state);

        //M[rowOut][col] = rand
        ptr64Out[0] = state[0];
        ptr64Out[1] = state[1];
        ptr64Out[2] = state[2];
        ptr64Out[3] = state[3];
	ptr64Out[4] = state[4];
	ptr64Out[5] = state[5];

	((uint64_t *) ptr64InOut)[0] ^= ((uint64_t *) state)[11];
	((uint64_t *) ptr64InOut)[1] ^= ((uint64_t *) state)[0];
	((uint64_t *) ptr64InOut)[2] ^= ((uint64_t *) state)[1];
	((uint64_t *) ptr64InOut)[3] ^= ((uint64_t *) state)[2];
	((uint64_t *) ptr64InOut)[4] ^= ((uint64_t *) state)[3];
	((uint64_t *) ptr64InOut)[5] ^= ((uint64_t *) state)[4];
	((uint64_t *) ptr64InOut)[6] ^= ((uint64_t *) state)[5];
	((uint64_t *) ptr64InOut)[7] ^= ((uint64_t *) state)[6];
	((uint64_t *) ptr64InOut)[8] ^= ((uint64_t *) state)[7];
	((uint64_t *) ptr64InOut)[9] ^= ((uint64_t *) state)[8];
	((uint64_t *) ptr64InOut)[10] ^= ((uint64_t *) state)[9];
	((uint64_t *) ptr64InOut)[11] ^= ((uint64_t *) state)[10];

	//Goes to next column (i.e., next block in sequence)
        ptr64InOut += BLOCK_LEN_INT128;
        ptr64In += BLOCK_LEN_INT128;
        ptr64Out += BLOCK_LEN_INT128;
    }
}

/**
 * Performs a duplex operation over "M[rowInOut] XOR M[rowIn]", using the output "rand"
 * to make "M[rowOut][col] = M[rowOut][col] XOR rand" and "M[rowInOut] = M[rowInOut] XOR rotW(rand)", 
 * where rotW is a 64-bit rotation to the left.
 *
 * @param state          The current state of the sponge 
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 * @param nCols          Number of Columns
 *
 */
void reducedDuplexRowSSE(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut, int nCols) {
    __m128i* ptr64InOut = rowInOut;     //pointer to row
    __m128i* ptr64In = rowIn;           //pointer to row'
    __m128i* ptr64Out = rowOut;         //pointer to row*
    int i;
    for (i = 0; i < nCols; i++) {
        //Absorbing "M[rowInOut] XOR M[rowIn]"
        state[0] = _mm_xor_si128(state[0], _mm_xor_si128(ptr64InOut[0], ptr64In[0]));
        state[1] = _mm_xor_si128(state[1], _mm_xor_si128(ptr64InOut[1], ptr64In[1]));
        state[2] = _mm_xor_si128(state[2], _mm_xor_si128(ptr64InOut[2], ptr64In[2]));
        state[3] = _mm_xor_si128(state[3], _mm_xor_si128(ptr64InOut[3], ptr64In[3]));
        state[4] = _mm_xor_si128(state[4], _mm_xor_si128(ptr64InOut[4], ptr64In[4]));
        state[5] = _mm_xor_si128(state[5], _mm_xor_si128(ptr64InOut[5], ptr64In[5]));

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyraSSE(state);

        //M[rowOut][col] = M[rowOut][col] XOR rand
        ptr64Out[0] = _mm_xor_si128(ptr64Out[0], state[0]);
        ptr64Out[1] = _mm_xor_si128(ptr64Out[1], state[1]);
        ptr64Out[2] = _mm_xor_si128(ptr64Out[2], state[2]);
        ptr64Out[3] = _mm_xor_si128(ptr64Out[3], state[3]);
        ptr64Out[4] = _mm_xor_si128(ptr64Out[4], state[4]);
        ptr64Out[5] = _mm_xor_si128(ptr64Out[5], state[5]);

        ((uint64_t *) ptr64InOut)[0] ^= ((uint64_t *) state)[11];
        ((uint64_t *) ptr64InOut)[1] ^= ((uint64_t *) state)[0];
        ((uint64_t *) ptr64InOut)[2] ^= ((uint64_t *) state)[1];
        ((uint64_t *) ptr64InOut)[3] ^= ((uint64_t *) state)[2];
        ((uint64_t *) ptr64InOut)[4] ^= ((uint64_t *) state)[3];
        ((uint64_t *) ptr64InOut)[5] ^= ((uint64_t *) state)[4];
        ((uint64_t *) ptr64InOut)[6] ^= ((uint64_t *) state)[5];
        ((uint64_t *) ptr64InOut)[7] ^= ((uint64_t *) state)[6];
        ((uint64_t *) ptr64InOut)[8] ^= ((uint64_t *) state)[7];
        ((uint64_t *) ptr64InOut)[9] ^= ((uint64_t *) state)[8];
        ((uint64_t *) ptr64InOut)[10] ^= ((uint64_t *) state)[9];
        ((uint64_t *) ptr64InOut)[11] ^= ((uint64_t *) state)[10];

        //Goes to next block
        ptr64Out += BLOCK_LEN_INT128;
        ptr64InOut += BLOCK_LEN_INT128;
        ptr64In += BLOCK_LEN_INT128;
    }
}

/**
 Prints an array of unsigned chars
 */
void printArray(unsigned char *array, unsigned int size, char *name) {
    int i;
    printf("%s: ", name);
    for (i = 0; i < size; i++) {
        printf("%2x|", array[i]);
    }
    printf("\n");
}
////////////////////////////////////////////////////////////////////////////////////////////////
