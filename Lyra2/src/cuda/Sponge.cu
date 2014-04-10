/**
 * A simple implementation of Blake2b's internal permutation 
 * in the form of a sponge.  Experimental CUDA implementation.
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
void initState(uint64_t state[/*16*/]){
    cudaMemset(state, 0,            64);  //first 512 bis are zeros
    if ( cudaSuccess != cudaGetLastError() ) {
        printf( "CUDA memory setting error in file %s, line %d!\n",  __FILE__, __LINE__  );
            printf( "Error: %s \n", cudaGetErrorString(cudaGetLastError()) );
            exit(EXIT_FAILURE);
    }

    uint64_t *state2 = &state[8];
    cudaMemcpy(state2, blake2b_IV,   64, cudaMemcpyHostToDevice);
    if ( cudaSuccess != cudaGetLastError() ) {
        printf( "CUDA memory copy error in file %s, line %d!\n",  __FILE__, __LINE__  );
            printf( "Error: %s \n", cudaGetErrorString(cudaGetLastError()) );
            exit(EXIT_FAILURE);
    }
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 * 
 * @param v     A uint64_t array to be processed by Blake2b's G function
 */
__device__ static void blake2bLyra2(uint64_t *v) {
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
*	Wrapper to call from CPU.
*/
__global__ static void blake2bLyra(uint64_t *v) {
    blake2bLyra2(v);
}



/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A uint64_t array to be processed by Blake2b's G function
 */
__device__ static void reducedBlake2bLyra2(uint64_t *v) {
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
void squeeze(uint64_t *state, byte *out, unsigned int len) {
    int fullBlocks = len / BLOCK_LEN_BYTES;
    cudaError_t  erro;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        cudaMemcpy(out + (BLOCK_LEN_BYTES * i), state, BLOCK_LEN_BYTES, cudaMemcpyDeviceToHost);
	
		erro = cudaGetLastError();
		if ( cudaSuccess !=  erro ) {
			printf( "Error in file %s, line %d!\n", __FILE__, __LINE__ );
			printf( "Error: %s \n", cudaGetErrorString(erro) );
		}

		blake2bLyra<<<1,1>>>(state);
		erro = cudaGetLastError();
		if ( cudaSuccess != erro ) {
			printf( "Error in file %s, line %d!\n", __FILE__, __LINE__ );
			printf( "Error: %s \n", cudaGetErrorString(erro) );
		}
    }
    
    //Squeezes remaining bytes
    cudaMemcpy(out + (BLOCK_LEN_BYTES * fullBlocks), state, (len % BLOCK_LEN_BYTES), cudaMemcpyDeviceToHost);
    if ( cudaSuccess != cudaGetLastError() ) {
		printf( "Erro no arquivo %s, na linha %d!\n", __FILE__, __LINE__ );
    }
}



/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed (BLOCK_LEN_INT64 words)
 */
__device__ void absorbBlock2(uint64_t *state, const uint64_t *in) {
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
	
    //Applies the transformation f to the sponge's state	
    blake2bLyra2(state);
}

/**
*	Wrapper to call from CPU.
*/
__global__ void absorbBlock(uint64_t *state, const uint64_t *in) {
    absorbBlock2(state, in);
}



/** 
 * Performs a squeeze operation for two rows in sequence, using 
 * reduced Blake2b's G function as the internal permutation
 * 
 * @param state     The current state of the sponge 
 * @param row0      Row to receive the data squeezed
 */
__global__ void reducedSqueezeRow(uint64_t* state, uint64_t* row0) {  // Já convertido
    uint64_t* ptr64 = row0;     // Pointer to position to be filled first (M[0])
    int i;
    for (i = 0; i < N_COLS; i++) {
        ptr64[0] = state[0];
        ptr64[1] = state[1];
        ptr64[2] = state[2];
        ptr64[3] = state[3];
        ptr64[4] = state[4];
        ptr64[5] = state[5];
        ptr64[6] = state[6];
        ptr64[7] = state[7];
        ptr64[8] = state[8];
        ptr64[9] = state[9];
        ptr64[10] = state[10];
        ptr64[11] = state[11];	
		
        //Goes to next block (column) that will receive the squeezed data		
        ptr64 += BLOCK_LEN_INT64;
		
        //Applies the reduced-round transformation f to the sponge's state        
		reducedBlake2bLyra2(state);
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
__device__ void reducedDuplexRowSetup2(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut){
    uint64_t* ptr64In = rowIn; 			//In Lyra2: pointer to prev
    uint64_t* ptr64InOut = rowInOut; 	//In Lyra2: pointer to row*
    uint64_t* ptr64Out = rowOut; 		//In Lyra2: pointer to row
    int i;
    for (i = 0; i < N_COLS; i++){
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
        reducedBlake2bLyra2(state);

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
*	Wrapper to call from CPU.
*/
__global__ void reducedDuplexRowSetup(uint64_t *state, uint64_t *rowa, uint64_t *prev, uint64_t *newRow){
    reducedDuplexRowSetup2(state, rowa, prev, newRow);
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
__device__ void reducedDuplexRow2(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut) {
    uint64_t* ptr64InOut = rowInOut; 	//In Lyra2: pointer to row*
    uint64_t* ptr64In = rowIn;          //In Lyra2: pointer to prev
    uint64_t* ptr64Out = rowOut; 		//In Lyra2: pointer to row
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
        reducedBlake2bLyra2(state);

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

        //Goes to next column (i.e., next block in sequence)
        ptr64Out += BLOCK_LEN_INT64;
        ptr64InOut += BLOCK_LEN_INT64;
        ptr64In += BLOCK_LEN_INT64;
    } 
}
 
/**
*	Wrapper to call from CPU.
*/ 
__global__ void reducedDuplexRow(uint64_t *state, uint64_t *prev, uint64_t *rowa, uint64_t *row) {
    reducedDuplexRow2(state, prev, rowa, row);
}


//====================== Setup Phase =====================//
__global__ void setupGPU(uint64_t *state, uint64_t *MemMatrix, int nRows){
    int rowa = 0;
    int row  = 2;
    int prev = 1;

    uint64_t*  ptr64a;
    uint64_t*  ptr64p;
    uint64_t*  ptr64n;

    do{

        ptr64p = &MemMatrix[(prev * ROW_LEN_INT64)];   // 0
        ptr64a = &MemMatrix[(rowa * ROW_LEN_INT64)];   // 1
        ptr64n = &MemMatrix[(row  * ROW_LEN_INT64)];   // 2

        reducedDuplexRowSetup2(state, ptr64p, ptr64a, ptr64n);

        //updates the value of row* (deterministically picked during Setup))
        rowa = rowa - 1;
        if(rowa < 0){
            rowa = prev;
        }
        //update prev: it now points to the last row ever computed
        prev = row;
        //updates row: does to the next row to be computed
        row = row + 1;
    } while (row < nRows );
}


//================== Wandering Phase =====================//  (stateDev, MemMatrixDev, timeCost, nRows, rowADev);
__global__ void wandering(uint64_t *state, uint64_t *MemMatrix, int timeCost, int nRows, int *rowA){
    int maxIndex = nRows - 1;
    int rowa = 0;		 	//index of row* (a previous row, deterministically picked during Setup and randomly picked during Wandering)
    int row = maxIndex;   	//index of row to be processed 
    int prev = 0;			//index of prev (last row ever computed/modified)
    int tau;				//Time Loop interator
    uint64_t * MemMatrixDev_P;
    uint64_t * MemMatrixDev_A;   
    uint64_t * MemMatrixDev_R;   

    for (tau = 1; tau <= timeCost; tau++){
        
        //========= Iterations for an odd tau  ==========
        row = maxIndex; //Odd iterations of the Wandering phase start with the last row ever computed
        prev = 0;       //The companion "prev" is 0
		
        do{
            //Selects a pseudorandom index row*
            //rowa = ((unsigned int)state[0] ^ prev) & maxIndex; //(USE THIS IF nRows IS A POWER OF 2)
            rowa = ((unsigned int)state[0] ^ prev) % nRows;		//(USE THIS FOR THE "GENERIC" CASE)

            MemMatrixDev_P = &MemMatrix[(prev * ROW_LEN_INT64)];
            MemMatrixDev_A = &MemMatrix[(rowa * ROW_LEN_INT64)];   
            MemMatrixDev_R = &MemMatrix[(row  * ROW_LEN_INT64)];   

            //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
            reducedDuplexRow2(state, MemMatrixDev_P , MemMatrixDev_A, MemMatrixDev_R);

            prev = row;
            row = row - 1;            
        } while (row >= 0);

        if (++tau > timeCost) {
            break; //end of the Wandering phase
        }
		
		//========= Iterations for an even tau  ==========
        row = 0;            //Even iterations of the Wandering phase start with row = 0
        prev = maxIndex;    //The companion "prev" is the last row in the memory matrix
        do {
            //rowa = ((unsigned int)state[0] ^ prev) & maxIndex; //(USE THIS IF nRows IS A POWER OF 2)
            rowa = ((unsigned int)state[0] ^ prev) % nRows;		//(USE THIS FOR THE "GENERIC" CASE)

            MemMatrixDev_P = &MemMatrix[(prev * ROW_LEN_INT64)];
            MemMatrixDev_A = &MemMatrix[(rowa * ROW_LEN_INT64)];   
            MemMatrixDev_R = &MemMatrix[(row  * ROW_LEN_INT64)];  
            
            //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
            reducedDuplexRow2(state, MemMatrixDev_P , MemMatrixDev_A, MemMatrixDev_R);
            
            //Goes to the next row (direct order)
            prev = row;
            row++;
        } while (row <= maxIndex);	
	}
	*rowA = rowa;
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
