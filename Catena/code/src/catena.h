#ifndef _CATENA_H_
#define _CATENA_H_

#include <stdint.h>
#include <string.h>

/* The default unit for all length values are bytes */

/* Recommended default values */
#define H_LEN      64
#define KEY_LEN    16
#define LAMBDA      3
#define GARLIC     18
#define MIN_GARLIC 18

/* Modes  */
#define PASSWORD_HASHING_MODE 0
#define KEY_DERIVATION_MODE   1
#define REGULAR 0
#define CLIENT 1



/* Return the reverse bit order of x where x is interpreted as n-bit value */
uint64_t reverse(uint64_t x, const uint8_t n);


/* This function computes the  \lambda-BRH of x. */
void LBRH(const uint8_t x[H_LEN], const uint8_t lambda,
	  const uint8_t garlic,   uint8_t h[H_LEN]);


/* Returns -1 if an an error occurred, otherwise 0. */
int Catena(const uint8_t *pwd,   const uint32_t pwdlen,
	   const uint8_t *salt,  const uint8_t  saltlen,
	   const uint8_t *data,  const uint32_t datalen,
	   const uint8_t lambda, const uint8_t  min_garlic,
	   const uint8_t garlic, const uint8_t hashlen,  uint8_t *hash);


/* API that assumes that the three parameter pwd, salt, and header
 * are all null-terminated string.
 * Returns -1 if an an error occurred, otherwise 0.
 */
int Naive_Catena(const char *pwd,  const char *salt, const char *data,
		 uint8_t hash[H_LEN]);


/* Returns -1 if an an error occurred, otherwise 0. */
int Simple_Catena(const uint8_t *pwd,   const uint32_t pwdlen,
		   const uint8_t *salt,  const uint8_t  saltlen,
		   const uint8_t *data,  const uint32_t datalen,
		   uint8_t hash[H_LEN]);


/* Expensive and memory consuming  password hashing part.
 * Returns -1 if an an error occurred, otherwise 0.
 */
int Catena_Client(const uint8_t *pwd,   const uint32_t pwdlen,
		  const uint8_t *salt,  const uint8_t  saltlen,
		  const uint8_t *data,  const uint32_t datalen,
		  const uint8_t lambda, const uint8_t  min_garlic,
		  const uint8_t garlic, const uint8_t  hashlen,
		  uint8_t x[H_LEN]);

/*  Computes the final step of the password hashing process. Requieres the
 *  output of Catena_Client(...) as input
 *  Returns -1 if an an error occurred, otherwise 0.
 */
int Catena_Server(const uint8_t garlic, const uint8_t x[H_LEN],
		  const uint8_t hashlen, uint8_t *hash);

/* Client independent update form an old hash */
void CI_Update(const uint8_t *old_hash,  const uint8_t lambda,
	       const uint8_t old_garlic, const uint8_t new_garlic,
	       const uint8_t hashlen, uint8_t *new_hash);


/* Mode of operation that derives a key from a password */
void Catena_KG(const uint8_t *pwd,   const uint32_t pwdlen,
	       const uint8_t *salt,  const uint8_t saltlen,
	       const uint8_t *data,  const uint32_t datalen,
	       const uint8_t lambda, const uint8_t  min_garlic,
	       const uint8_t garlic, uint32_t keylen,
	       const uint8_t key_id, uint8_t *key);


/* Encrypts the password hash with H(key || uuid || key) where
   key denots a KEY_LEN-byte key and uuid denots a *UNIQUE* user ID */
void Catena_Keyed_Hashing(const uint8_t *pwd,   const uint32_t pwdlen,
			  const uint8_t *salt,  const uint8_t  saltlen,
			  const uint8_t *data,  const uint32_t datalen,
			  const uint8_t lambda, const uint8_t  min_garlic,
			  const uint8_t garlic, const uint8_t  hashlen,
			  const uint8_t *key,   const uint64_t uuid,
			  uint8_t *chash);


/* Returns -1 if an an error occurred, otherwise 0. */
int PHS(void *out, size_t outlen,  const void *in, size_t inlen,
	const void *salt, size_t saltlen, unsigned int t_cost,
	unsigned int m_cost);
#endif
