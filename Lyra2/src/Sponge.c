/**
 * A simple implementation of Blake2b's internal permutation 
 * in the form of a sponge.
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
inline void initState(uint64_t state[/*16*/]) {
    memset(state, 0, 64); //first 512 bis are zeros
    state[8] = blake2b_IV[0];
    state[9] = blake2b_IV[1];
    state[10] = blake2b_IV[2];
    state[11] = blake2b_IV[3];
    state[12] = blake2b_IV[4];
    state[13] = blake2b_IV[5];
    state[14] = blake2b_IV[6];
    state[15] = blake2b_IV[7];
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 * 
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
inline static void blake2bLyra(uint64_t *v) {
    ROUND_LYRA(0);
    ROUND_LYRA(1);
    ROUND_LYRA(2);
    ROUND_LYRA(3);
    ROUND_LYRA(4);
    ROUND_LYRA(5);
    ROUND_LYRA(6);
    ROUND_LYRA(7);
    ROUND_LYRA(8);
    ROUND_LYRA(9);
    ROUND_LYRA(10);
    ROUND_LYRA(11);
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
inline static void reducedBlake2bLyra(uint64_t *v) {
    ROUND_LYRA(0);
}

/**
 * Performs a squeeze operation, using Blake2b's G function as the 
 * internal permutation
 * 
 * @param state      The current state of the sponge 
 * @param out        Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
inline void squeeze(uint64_t *state, byte *out, unsigned int len) {
    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *ptr = out;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        memcpy(ptr, state, BLOCK_LEN_BYTES);
        blake2bLyra(state);
        ptr += BLOCK_LEN_BYTES;
    }

    //Squeezes remaining bytes
    memcpy(ptr, state, (len % BLOCK_LEN_BYTES));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed (BLOCK_LEN_INT64 words)
 */
inline void absorbBlock(uint64_t *state, const uint64_t *in) {
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] ^= in[0];
    state[1] ^= in[1];
    state[2] ^= in[2];
    state[3] ^= in[3];
    state[4] ^= in[4];
    state[5] ^= in[5];
    state[6] ^= in[6];
    state[7] ^= in[7];
    state[8] ^= in[8];
    state[9] ^= in[9];
    state[10] ^= in[10];
    state[11] ^= in[11];
    //printArray(state, 128, "state");

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
}

/** 
 * Performs a squeeze operation for two rows in sequence, using 
 * reduced Blake2b's G function as the internal permutation
 * 
 * @param state     The current state of the sponge 
 * @param row       Row to receive the data squeezed
 */
inline void reducedSqueezeRow(uint64_t* state, uint64_t* row) {
    int i;
    //M[row][col] = H.reduced_squeeze()
    for (i = 0; i < N_COLS; i++) {
        row[0] = state[0];
        row[1] = state[1];
        row[2] = state[2];
        row[3] = state[3];
        row[4] = state[4];
        row[5] = state[5];
        row[6] = state[6];
        row[7] = state[7];
        row[8] = state[8];
        row[9] = state[9];
        row[10] = state[10];
        row[11] = state[11];
         
        //Goes to next block (column) that will receive the squeezed data
        row += BLOCK_LEN_INT64;
        
        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);
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
 *
 */
inline void reducedDuplexRowSetup(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut) {
    uint64_t* ptr64In = rowIn; 		//In Lyra2: pointer to prev
    uint64_t* ptr64InOut = rowInOut; 	//In Lyra2: pointer to row*
    uint64_t* ptr64Out = rowOut; 	//In Lyra2: pointer to row
    int i; 
    for (i = 0; i < N_COLS; i++) {
        //Absorbing "M[rowInOut] XOR M[rowIn]"
        state[0] ^= ptr64InOut[0] ^ ptr64In[0];
        state[1] ^= ptr64InOut[1] ^ ptr64In[1];
        state[2] ^= ptr64InOut[2] ^ ptr64In[2];
        state[3] ^= ptr64InOut[3] ^ ptr64In[3];
        state[4] ^= ptr64InOut[4] ^ ptr64In[4];
        state[5] ^= ptr64InOut[5] ^ ptr64In[5];
        state[6] ^= ptr64InOut[6] ^ ptr64In[6];
        state[7] ^= ptr64InOut[7] ^ ptr64In[7];
        state[8] ^= ptr64InOut[8] ^ ptr64In[8];
        state[9] ^= ptr64InOut[9] ^ ptr64In[9];
        state[10] ^= ptr64InOut[10] ^ ptr64In[10];
        state[11] ^= ptr64InOut[11] ^ ptr64In[11];
        
        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);

        //M[rowOut][col] = rand
        ptr64Out[0] = state[0];
        ptr64Out[1] = state[1];
        ptr64Out[2] = state[2];
        ptr64Out[3] = state[3];
        ptr64Out[4] = state[4];
        ptr64Out[5] = state[5];
        ptr64Out[6] = state[6];
        ptr64Out[7] = state[7];
        ptr64Out[8] = state[8];
        ptr64Out[9] = state[9];
        ptr64Out[10] = state[10];
        ptr64Out[11] = state[11];


        //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
        ptr64InOut[0] ^= state[11];
        ptr64InOut[1] ^= state[0];
        ptr64InOut[2] ^= state[1];
        ptr64InOut[3] ^= state[2];
        ptr64InOut[4] ^= state[3];
        ptr64InOut[5] ^= state[4];
        ptr64InOut[6] ^= state[5];
        ptr64InOut[7] ^= state[6];
        ptr64InOut[8] ^= state[7];
        ptr64InOut[9] ^= state[8];
        ptr64InOut[10] ^= state[9];
        ptr64InOut[11] ^= state[10];

        //Goes to next column (i.e., next block in sequence)
        ptr64InOut += BLOCK_LEN_INT64;
        ptr64In += BLOCK_LEN_INT64;
        ptr64Out += BLOCK_LEN_INT64;
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
 *
 */
inline void reducedDuplexRow(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut) {
    uint64_t* ptr64InOut = rowInOut; 	//In Lyra2: pointer to row*
    uint64_t* ptr64In = rowIn;          //In Lyra2: pointer to prev
    uint64_t* ptr64Out = rowOut; 	//In Lyra2: pointer to row
    int i;
    for (i = 0; i < N_COLS; i++) {
	
	//Absorbing "M[rowInOut] XOR M[rowIn]"
        state[0] ^= ptr64InOut[0] ^ ptr64In[0];
        state[1] ^= ptr64InOut[1] ^ ptr64In[1];
        state[2] ^= ptr64InOut[2] ^ ptr64In[2];
        state[3] ^= ptr64InOut[3] ^ ptr64In[3];
        state[4] ^= ptr64InOut[4] ^ ptr64In[4];
        state[5] ^= ptr64InOut[5] ^ ptr64In[5];
        state[6] ^= ptr64InOut[6] ^ ptr64In[6];
        state[7] ^= ptr64InOut[7] ^ ptr64In[7];
        state[8] ^= ptr64InOut[8] ^ ptr64In[8];
        state[9] ^= ptr64InOut[9] ^ ptr64In[9];
        state[10] ^= ptr64InOut[10] ^ ptr64In[10];
        state[11] ^= ptr64InOut[11] ^ ptr64In[11];
        
        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);

	//M[rowOut][col] = M[rowOut][col] XOR rand
        ptr64Out[0] ^= state[0];
        ptr64Out[1] ^= state[1];
        ptr64Out[2] ^= state[2];
        ptr64Out[3] ^= state[3];
        ptr64Out[4] ^= state[4];
        ptr64Out[5] ^= state[5];
        ptr64Out[6] ^= state[6];
        ptr64Out[7] ^= state[7];
        ptr64Out[8] ^= state[8];
        ptr64Out[9] ^= state[9];
        ptr64Out[10] ^= state[10];
        ptr64Out[11] ^= state[11];

	//M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
        ptr64InOut[0] ^= state[11];
        ptr64InOut[1] ^= state[0];
        ptr64InOut[2] ^= state[1];
        ptr64InOut[3] ^= state[2];
        ptr64InOut[4] ^= state[3];
        ptr64InOut[5] ^= state[4];
        ptr64InOut[6] ^= state[5];
        ptr64InOut[7] ^= state[6];
        ptr64InOut[8] ^= state[7];
        ptr64InOut[9] ^= state[8];
        ptr64InOut[10] ^= state[9];
        ptr64InOut[11] ^= state[10];

        //Goes to next block
        ptr64Out += BLOCK_LEN_INT64;
        ptr64InOut += BLOCK_LEN_INT64;
        ptr64In += BLOCK_LEN_INT64;
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
