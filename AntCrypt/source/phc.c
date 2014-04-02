#include <inttypes.h>    /* C99 fixed-width integer types w/ output macros */
#include <math.h>        /* pow */
#include <openssl/sha.h> /* for SHA512 */
#include <stdio.h>       /* printf */
#include <stdlib.h>      /* malloc */
#include <string.h>      /* memcpy, memset */

/* PHS definitions, types and prototypes */
#include "phc_debug.h"   /* Debug only: Dprintf, DprintState macros */
#include "phc.h"

/* global variables some statistics in STATISTICS mode */
#ifdef PHC_DEBUG_STATISTICS
uint64_t cnt_idx[PHS_F_COUNT];
uint64_t *cnt_tgt_addr;
#endif

/* TODO for next revision:
 *
 * Sanity check of input parameters (length of password)
 * Better error code on failures (some definitions already prepared)
 */

/* F function mapping */
uint32_t F (uint8_t idx, uint32_t v0) {
	/* choose function based on idx */
	switch(idx) {
		case  0:  return( F00(v0) );
		case  1:  return( F01(v0) );
		case  2:  return( F02(v0) );
		case  3:  return( F03(v0) );
		case  4:  return( F04(v0) );
		case  5:  return( F05(v0) );
		case  6:  return( F06(v0) );
		case  7:  return( F07(v0) );
		case  8:  return( F08(v0) );
		case  9:  return( F09(v0) );
		case 10:  return( F10(v0) );
		case 11:  return( F11(v0) );
		case 12:  return( F12(v0) );
		case 13:  return( F13(v0) );
		case 14:  return( F14(v0) );
		case 15:  return( F15(v0) );
		default:  return( F15(v0) );
	}
}

/* initializes the state */
void phs_init(phs_ctx_t *ctx, const uint8_t *salt, const uint8_t *pw, size_t pwlen) {
	uint8_t *state = (uint8_t *) ctx->state;
	uint16_t offset = 0;

	Dprintf("DEBUG: phs_init() called.\n");
	Dprintf("DEBUG: pw is \'%s\' of length %d\n", pw, (int) pwlen);

	/* copy salt to start of array */
	memcpy(state, salt, PHS_SALT_SIZE);
	offset += PHS_SALT_SIZE;
	
	/* append password */
	memcpy(state+offset, pw, pwlen);
	offset += pwlen;

	/* append 0x80 */
	state[PHS_SALT_SIZE + pwlen] = 0x80;
	offset++;

	/* clear remaining bytes */
	// TODO is it a good choice to just clear it? would we increase security by doing something else?
	// if there are security concerns: 
	memset(state + offset, 0x00, ctx->state_bytes - offset);

	/* distribute entropy across the state */
	phs_upd_entropy(ctx);
}

/* This function derives the new state from the current hash stored in
 * ctx.rehash and is called by the phs_upd_entropy() function.
 *
 * In addition, we use this function to update previously generated key
 * material to a higher t_cost parameter.
 */
void phs_store_derived_state(phs_ctx_t *ctx) {
	/* compute the number of 64-byte blocks needed to update the full state */
	uint32_t num_hashs = ctx->state_bytes / PHS_HASH_SIZE;
	/* input is the full rehash state, counting in the rehashprefix */
	uint8_t *in        = (uint8_t *) ctx->rehashprefix;
	uint32_t *cnt      = ctx->rehashprefix;
	uint8_t *out       = (uint8_t *) ctx->state;

	/* redistribute entropy evenly across the state */
	for (*cnt = 0; (*cnt) < num_hashs; (*cnt)++) {
		/* compute SHA512 and update state */
		SHA512(in, PHS_REHASH_SIZE, out);
		/* move output pointer */
		out += PHS_HASH_SIZE;
	}
}

/* The function phs_upd_entropy re-distributes the entopy across the full state
 * using hash function calls. In the current implementation, only one hash function
 * (SHA-512) is called.
 *
 * It updates the full memory referenced by ctx.state.
 */ 
void phs_upd_entropy(phs_ctx_t *ctx) {
	uint8_t *state = (uint8_t *) ctx->state;
	uint8_t *rehash = (uint8_t *) ctx->rehash;
	
	/* debug output */
	Dprintf("Executing phs_upd_entropy().\n");
	Dprintf("Dumping current state...\n");
	DprintFullState(ctx);

	/* update rehash buffer */
	Dprintf("Dumping rehash-buffer after phs_update_rehash_buffer()...\n");
	SHA512(state, ctx->state_bytes, rehash);
	DprintRehashState(ctx);

	/* derive the state by rehashing the rehash buffer */
	Dprintf("Dumping new state ater phs_store_derived_state()...\n");
	phs_store_derived_state(ctx);
	DprintFullState(ctx);
}

void phs_upd_state(phs_ctx_t *ctx) {
	uint32_t *state = (uint32_t*) ctx->state;
	uint8_t idx_perm[PHS_F_COUNT];
	uint8_t idx;
	uint32_t tgt_addr;
	uint32_t res;

	for (uint32_t i = 0; i < ctx->inner_rounds; i++) {
		Dprintf("DEBUG: Starting inner round %d...", i);
		for (uint32_t j = 0; j < ctx->state_words; j++) {
			/* Retrieve state value of current round and ensure that the value
			 * is modified with each inner round. We use the "res" value, as
			 * the intermediate result is used to continue the sequence in the
			 * inner loop.
			 */
			res = state[j];
			res = ROTR(res, i % 32);
			tgt_addr = res % ctx->state_words;

			Dprintf("DEBUG: pos = %" PRIu32 ", tgt_addr = %" PRIu32 "\n", j, tgt_addr);

			/* We execute a sequence of PHS_F_COUNT functions as one iteration,
			 * which corresponds to one of all PHS_F_COUNT! possible permutations
			 * of the functions.
			 * This ensures that the "block" is executed in constant time,
			 * regardless of the target platform. It also ensures constant time
			 * between two memory accesses.
			 */
			
			/* Reset permutation index */
			for (uint8_t i = 0; i < PHS_F_COUNT; i++) {
				idx_perm[i] = i;
			}

			/* Execute a specific sequence (permutation) using all functions */
			for (uint8_t k = 0; k < PHS_F_COUNT; k++) {	
				/* Derive the function index from the intermediate result in constant
				 * time for each step.
				 *
				 * 1) It reads the value "idx" at position r(i) from the array "perm"
				 * 2) It reads the value "tmp" at position PHS_F_COUNT-k from the array "perm"
				 * 3) It overwrites the value at position r(i) with "tmp"
				 * 
				 * Example: n = 7, init perm = [0, 1, 2, 3, 4, 5, 6], 0 <= r(i) < n-i in step i
				 *  Step 0: r(0) = 4, idx = perm[4] = 4, new perm = [0, 1, 2, 3, 6, 5| 6]
				 *  Step 1: r(1) = 5, idx = perm[5] = 5, new perm = [0, 1, 2, 3, 6| 5, 6]
				 *  Step 2: r(2) = 2, idx = perm[2] = 2, new perm = [0, 1, 6, 3| 6, 5, 6]
				 *  Step 3: r(3) = 2, idx = perm[2] = 6, new perm = [0, 1, 3| 3, 6, 5, 6]
				 *  Step 4: r(4) = 0, idx = perm[0] = 0, new perm = [3, 1| 3, 3, 6, 5, 6]
				 *  Step 5: r(5) = 1, idx = perm[1] = 1, new perm = [3| 1, 3, 3, 6, 5, 6]
				 *  Step 6: r(6) = 0, idx = perm[0] = 3, new perm = [3, 1, 3, 3, 6, 5, 6]
				 *
				 * Please note that we can optimize this step in C by just changing the
				 * pointers...
				 */
				idx = idx_perm[res % (PHS_F_COUNT-k)];
				idx_perm[res % (PHS_F_COUNT-k)] = idx_perm[PHS_F_COUNT-k-1];
				Dprintf("DEBUG: >> using idx = %d, coming from pos %d\n", idx, (res % (PHS_F_COUNT-k)));

				/* Evaluate function idx for res */
				res = F(idx, res);
				/* *********** Begin DEBUG-only statistics *********** */
#ifdef PHC_DEBUG_STATISTICS
				/* increase counters */
				cnt_idx[idx]++;
#endif	
				/* *********** End DEBUG-only statistics *********** */

				/* debug output */
				Dprintf("DEBUG: >> k = %02d, idx = %d, res = %08" PRIx32 "\n", k, idx, res);
			}

			/* XOR the result of the sequence to the target value */
			state[tgt_addr] ^= res;
			/* *********** Begin DEBUG-only statistics *********** */
#ifdef PHC_DEBUG_STATISTICS
			cnt_tgt_addr[tgt_addr]++;
#endif	
			/* *********** End DEBUG-only statistics *********** */
		}
	}
}

/* This function generates the output of the password hashing function.
 *
 * The output consists of a variable length of bits, starting with the output of
 * hash(state). If the output length is at least PHS_HASH_SIZE, this allows us to re-use
 * the information to upgrade previously generated passwords to a higher t_cost parameter.
 */
void phs_gen_output(phs_ctx_t *ctx, size_t outlen, void* out) {
	uint32_t output_block;
	uint32_t output_remaining = outlen;
	uint8_t *out_u8 = (uint8_t *) out;

	/* Hash the entire state using SHA512 and store it in the rehash buffer temporarily */
	SHA512((uint8_t *) ctx->state, ctx->state_bytes, (uint8_t*) ctx->rehash);

	/* In order to create additional key material, we rehash the current state
	 * and add a 32-bit word in front until we created enough output bits...
	 *
	 * If we use up to PHS_HASH_SIZE byte, we simply copy the hash to the output buffer.
	 */
	if (outlen <= PHS_HASH_SIZE) {
		memcpy(out_u8, (uint8_t*) ctx->rehash, outlen);
	}
	/* In order to create additional key material, we rehash the current state
	 * and add a 32-bit word in front until we created enough output bits...
	 */
	else {
		memcpy(out_u8, (uint8_t*) ctx->rehash, PHS_HASH_SIZE);

		/* Update the pointers and the remaining byte count */
		out_u8 += PHS_HASH_SIZE;
		output_remaining = outlen - PHS_HASH_SIZE;

		/* initialize the state prefix with 1 */
		*(ctx->stateprefix) = 1;

		/* copy additional output to the output buffer */
		while (output_remaining != 0) {
			/* Now, we hash the entire state with the updated prefix and store it in rehash */
			SHA512((uint8_t *) ctx->stateprefix, ctx->state_bytes + sizeof(uint32_t), ctx->rehash);

			/* And derive a new state as additional key material */
			phs_store_derived_state(ctx);
	
			/* Set the block size to either the full state or a partial state */
			if (output_remaining < ctx->state_bytes) {
				output_block = output_remaining;
			}
			else {
				output_block = ctx->state_bytes;
			}
	
			/* copy to output buffer */
			memcpy(out_u8, ctx->state, output_block);

			/* update remaining bytes and modify output pointer */
			output_remaining -= output_block;
			out_u8 += output_block;

			/* increment the state prefix in case we need even more output */
			*(ctx->stateprefix) = *(ctx->stateprefix) + 1;
		} while (output_remaining != 0);
	}

}

/* TODO update description */
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
	phs_ctx_t ctx;

	/* *********** initialization steps *********** */

	// derive state size from somewhere
	ctx.state_bytes = pow(2, m_cost+8);       /* we use at least 256 byte as the state */
	ctx.state_words = ctx.state_bytes >> 2;   /* we operate on 32-bit words */
	ctx.inner_rounds = m_cost >> 4;           /* number of times the whole state is overwritten */
	if (ctx.inner_rounds < 2) {               /* use at least two inner rounds! */
		ctx.inner_rounds = 2;
	}
	ctx.outer_rounds = t_cost;                /* number of times we rehash */
	if (ctx.outer_rounds == 0) {              /* use at least one outer round! */
		ctx.outer_rounds = 1;
	}

	/* allocate memory for the full state (32-bit counter + state) and rehashing */
	Dprintf("DEBUG: Allocating %"PRIu64" bytes of memory for prefixed state buffer...\n", (ctx.state_words + 1) * sizeof(uint32_t));
	ctx.stateprefix = (uint32_t *) calloc(ctx.state_words + 1, sizeof(uint32_t));
	Dprintf("DEBUG: Allocating %"PRIu64" bytes of memory for rehashing buffer...\n", ((PHS_REHASH_SIZE/4) + 1) * sizeof(uint32_t));
	ctx.rehashprefix = (uint32_t *) calloc((PHS_REHASH_SIZE/4), sizeof(uint32_t));

	/* set the ctx.state and ctx.rehash pointers to the non-prefixed buffer */
	ctx.state = ctx.stateprefix + 1;
	ctx.rehash = ctx.rehashprefix + 1;

	/* initialize state from pw and salt */
	Dprintf("DEBUG: initializing state with password and salt...\n");
	phs_init(&ctx, salt, in, inlen);

	/* **** end of initialization **** */
	Dprintf("Info : we could wipe the pw and salt now...\n");

	/* *********** Begin DEBUG-only statistics *********** */
#ifdef PHC_DEBUG_STATISTICS
	/* allocate space and clear counter values */
	for (int i = 0; i < PHS_F_COUNT; i++) {
		cnt_idx[i] = 0;
	}
	/* allocate and clear memory for address counters */
	cnt_tgt_addr = (uint64_t*) calloc(ctx.state_words, sizeof(uint64_t));
#endif	
	/* *********** End DEBUG-only statistics *********** */
	
	/* *********** time wasting computation steps *********** */
	for (uint32_t i = 0; i < ctx.outer_rounds; i++) {
		Dprintf("DEBUG: executing outer round: %" PRIu32 " \n", i);
		/* perform multiple calls to function F and scramble the bits in the state */
		phs_upd_state(&ctx);
		/* re-distribute entropy */
		phs_upd_entropy(&ctx);
	}

	/* generate 'outlen' bytes of output and store it in 'out' */
	phs_gen_output(&ctx, outlen, out);

	/* Clean up the memory we allocated */
	Dprintf("DEBUG: freeing state...\n");
	free(ctx.stateprefix);
	Dprintf("DEBUG: freeing rehash...\n");
	free(ctx.rehashprefix);

	/* *********** Begin DEBUG-only statistics *********** */
#ifdef PHC_DEBUG_STATISTICS
	printf("********* Statistics **********\n");
	double rounds = ctx.inner_rounds * ctx.state_words * ctx.outer_rounds;
	printf("Function calls:\n");
	for (int i = 0; i < PHS_F_COUNT; i++) {
		double usage = (cnt_idx[i] / rounds) * 100;
		printf("F[%d]: %07.4lf%% (%" PRIu64 ")\n", i, usage, cnt_idx[i]);
	}
	printf("State usage as [tgt] addresses: \n");
	for (int i = 0; i < ctx.state_words; i++) {
		double tgt_usage = (cnt_tgt_addr[i] / rounds) * 100;
		printf("[%08.6lf%%] ", tgt_usage);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("Memory used: %" PRIu32 " byte, functions called: %0.0lf\n", ctx.state_bytes, rounds);

	free(cnt_tgt_addr);
#endif	
	/* *********** End DEBUG-only statistics *********** */
	
	return 0;
}
