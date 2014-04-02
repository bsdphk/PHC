/*
 * Omega Crypt (ocrypt)
 * Brandon Enright <bmenrigh@brandonenright.net>
 * http://www.brandonenright.net/ocrypt/
 *
 * 2014-03-31
 *
 * Placed in the public domain.
 *
 * Submitted to the Password Hashing Competition
 * https://password-hashing.net/index.html
 */


#include "ocrypt.h"


/* Lengths are in bytes */
int ocrypt(uint8_t *out, size_t outlen, uint8_t *in, size_t inlen,
	   uint8_t *salt, size_t saltlen, uint8_t *key, size_t keylen,
	   unsigned int t_cost, unsigned int m_cost) {

  uint8_t params[OCRYPT_PARAMS_SIZE];
  uint8_t chash_out[CHASHSTATESIZE];
  struct chacha_wrapper_ctx chawctx;
  uint8_t chacha_key[32];
  uint8_t chacha_iv[8];
  uint64_t t_iterations;
  uint32_t m_array_size;
  uint32_t m_array_mask;
  uint64_t *state_array;
  uint8_t branch_select;
  uint64_t tmp64;

  /* For the state array manipulation */
  uint64_t carry;
  uint32_t tad_a, tad_b;
  uint64_t tval_a, tval_b;

  uint64_t i; /* Simple iterator */

  /* 
   * Omega Crypt accepts output lengths of {128, 160, 224, 256, 384, 512} bits
   */
  if ((outlen != (128 / 8)) && (outlen != (160 / 8)) &&
      (outlen != (224 / 8)) && (outlen != (256 / 8)) &&
      (outlen != (384 / 8)) && (outlen != (512 / 8))) {
    return OCRYPT_E_OLEN;
  }

  /* 
   * Omega Crypt accepts passwords, salts, and personalized keys of length
   * less than or equal 255 bytes
   */
  if (inlen >= 256) {
    return OCRYPT_E_PLEN;
  }
  if (saltlen >= 256) {
    return OCRYPT_E_SLEN;
  }
  if (keylen >= 256) {
    return OCRYPT_E_KLEN;
  }

  /*
   * Omega Crypt accepts time and memory costs parametrs between 0 and 14
   * inclusive.
   *
   * 0 time cost corresponds to 2^17 (131072) cipher-dependent branches
   * 14 time cost corresponds to 2^31 (2147483648) cipher-dependent branches
   *
   * 0 memory cost corresponds to 1 MiB of memory usage
   * 14 memory cost corresponds to 16 GiB of memory usage
   *
   */
  if (t_cost > OCRYPT_MAX_TCOST) {
    return OCRYPT_E_TCOST;
  }
  if (m_cost > OCRYPT_MAX_MCOST) {
    return OCRYPT_E_MCOST;
  }

  /* 
   * Omega Crypt pads the password, salt, and key with null-bytes each to
   * a length of 255 bytes and then the 256th byte is set to the length
   * of each, respectively.  Once padded, the three are laid out in
   * order <password><salt><key> and then three additional bytes are
   * appened, one for each of the output size, time cost, and memory cost,
   * in than order for a total of (256 * 3) + 3 = 771 bytes.
   */

  /* Do the "padding" all in one step */
  memset(params, 0, OCRYPT_PARAMS_SIZE);
  /* Copy in the password input bytes */
  for (i = 0; i < inlen; i++) {
    params[i] = in[i];
  }
  params[255] = inlen; /* Set the 256th password byte to inlen */
  /* Copy in the salt input bytes */
  for (i = 0; i < saltlen; i++) {
    params[256 + i] = salt[i];
  }
  params[256 + 255] = saltlen; /* Set the 256th salt byte to saltlen */
  /* Copy in the key input bytes */
  for (i = 0; i < keylen; i++) {
    params[(256 * 2) + i] = key[i];
  }
  params[(256 * 2) + 255] = keylen; /* Set the 256th key byte to keylen */
  /* Set the remaining three bytes to outlen, t_cost, and m_cost */
  params[(256 * 3) + 0] = outlen;
  params[(256 * 3) + 1] = t_cost;
  params[(256 * 3) + 2] = m_cost;

  /* 
   * Omega Crypt hashes the 771-byte parameter input
   * with cubehash160+16/32+160-256 to derive a 256-bit key
   * for use with the ChaCha stream cipher.  The ChaCha IV
   * is set to 64-bits of zeros to allow for replacing ChaCha
   * with another stream cipher that doesn't take an IV.
   */
  chash_message(160, 16, 32, 160, 256,
		(uint8_t *)params, OCRYPT_PARAMS_SIZE, &chash_out);
  memcpy(chacha_key, chash_out, 32); /* Get the 256 bit hash output */
  memset(chacha_iv, 0, 8);
  o_chacha_init(&chawctx, &chacha_key, &chacha_iv);

  /* 
   * Omega Crypt allocates a state array of 2^m_cost 64-bit words.
   * For initialization and finalization it is treated as an array of
   * bytes and for random access it is treated as an arary of
   * little-endian 64-bit words.
   *
   * Initialization sets the first 771 bytes to the parameter input
   * used to derrive the ChaCha key and the remaining bytes to zero.
   * Then ChaCha is used to encrypt (XOR) all of the 64-bit words.
   */
  m_array_size = 1 << (m_cost + OCRYPT_BASE_MCOST);
  m_array_mask = m_array_size - 1; /* Useful for bitwise-and */

  state_array = calloc(m_array_size, 8); /* allocates zero'd-mem */

  if (state_array == NULL) {
    return OCRYPT_E_MEM;
  }

  /* Copy in the params bytes */
  memcpy(state_array, params, OCRYPT_PARAMS_SIZE);

  /* Encrypt the state with ChaCha output */
  for (i = 0; i < m_array_size; i++) {
    o_chacha_getbytes(&chawctx, (uint8_t *)&tmp64, 8);
    state_array[i] ^= tmp64;
  }

  /*
   * Omega Crypt manipulates the state array 2^t_cost times using
   * the output of ChaCha as the guide.
   *
   * For each iteration, a byte of ChaCha output is used to select
   * between four possible branches of manipulation.  A 64-bit carry
   * value is initialized and used between iterations to enforce
   * data dependancy from each iteration to the next;
   */
  
  t_iterations = 1 << (t_cost + OCRYPT_BASE_TCOST);

  o_chacha_getbytes(&chawctx, (uint8_t *)&carry, 8);
  for (i = 0; i < t_iterations; i++) {
    o_chacha_getbytes(&chawctx, (uint8_t *)&branch_select, 1);
    branch_select &= 3; /* Zero all but lower 2 bits */

    if (branch_select == 0) {
      o_chacha_getbytes(&chawctx, (uint8_t *)&tad_a, 4);
      tad_a &= m_array_mask;
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_a, 8);

      state_array[tad_a] += carry;
      carry ^= tval_a;
    }
    else if (branch_select == 1) {
      o_chacha_getbytes(&chawctx, (uint8_t *)&tad_a, 4);
      tad_a ^= 0x0a1b2c3d;
      tad_a &= m_array_mask;
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_a, 8);

      state_array[tad_a] ^= carry;
      carry += tval_a;
    }
    else if (branch_select == 2) {
      o_chacha_getbytes(&chawctx, (uint8_t *)&tad_a, 4);
      tad_a ^= 0xfedc0123;
      tad_a &= m_array_mask;
      o_chacha_getbytes(&chawctx, (uint8_t *)&tad_b, 4);
      tad_b ^= 0xfedc0123;
      tad_b &= m_array_mask;
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_a, 8);
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_b, 8);

      state_array[tad_a] ^= tval_a;
      state_array[tad_b] += (tval_b ^ carry);
      carry ^= state_array[carry & m_array_mask];
    }
    else if (branch_select == 3) {
      o_chacha_getbytes(&chawctx, (uint8_t *)&tad_a, 4);
      tad_a ^= 0x76543210;
      tad_a &= m_array_mask;
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_a, 8);
      o_chacha_getbytes(&chawctx, (uint8_t *)&tval_b, 8);
      
      state_array[state_array[tad_a] & m_array_mask] += (carry ^ tval_a);
      carry += (state_array[tad_a] ^ tval_b);
    }

  }

  /*
   * Omega Hash applies hashes to the whole state array to derive
   * the final hash output using cubehash16+8/64+320-N 
   * for an N-bit output.
   */
  chash_message(16, 8, 64, 320, outlen * 8,
                (uint8_t *)state_array, m_array_size * 8, &chash_out);  
  memcpy(out, chash_out, outlen); /* Get N-bit final output */

  /* Give back all of that memory */
  free(state_array);
  
  return OCRYPT_SUCCESS;
}


