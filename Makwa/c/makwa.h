/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

#ifndef MAKWA_H__
#define MAKWA_H__

#include <stddef.h>

/*
 * This file defines the API for the Makwa reference C implementation.
 * For details on Makwa usage and parameters, please refer to the
 * Makwa specification.
 *
 * CONVENTIONS:
 * ------------
 *
 * All functions with an 'int' return type return either 0 (MAKWA_OK, on
 * success), or a negative error code (e.g. MAKWA_NOMEM on internal memory
 * allocation error).
 *
 * No pointer-type parameter may be set to NULL unless explicitly allowed.
 * Passing NULL to a parameter which the function expects to be non-NULL
 * triggers undefined behaviour (e.g. a segmentation fault, or silent
 * data corruption...).
 *
 * All character strings are zero-terminated. For input passwords, it is
 * conventionally suggested that UTF-8 encoding is used, as per the
 * Makwa specification, section A.1. It is up to the caller to ensure
 * proper encoding. The internals of Makwa are encoding-agnostic: the
 * input is handled as a sequence of bytes.
 *
 *
 * OUTPUT BUFFER SEMANTICS:
 * ------------------------
 *
 * When a function returns variable length data (e.g. a hash output),
 * it takes two arguments: a pointer to void (e.g. 'out') and a pointer
 * to size_t (e.g. 'out_len'). The behaviour is then the following:
 *
 * -- If both 'out' and 'out_len' are NULL then the function simply
 * ignores these parameters; the output is not produced; the function
 * returns 0 (MAKWA_OK) unless some other parameter triggers an error.
 *
 * -- If 'out' is NULL but 'out_len' is not, then '*out_len' is filled
 * with the length (in bytes) of the data that would have been produced.
 * The function still returns 0 (MAKWA_OK). The previous value of
 * '*out_len' is ignored. When the output is a character string, the
 * returned length includes the terminating 0.
 *
 * -- If 'out' is not NULL but 'out_len' is NULL, then the output is
 * produced and written into the buffer pointed to by 'out'. That buffer
 * is deemed large enough. The caller is responsible for having allocated
 * a large enough buffer so as to avoid any overflow.
 *
 * -- If 'out' is not NULL, and 'out_len' is not NULL either, then
 * '*out_len' is first read; it is supposed to contain the length of the
 * buffer pointed to by 'out'. If that length is insufficient to accomodate
 * the result, then the actual output length is written in '*out_len',
 * but the output is not produced, and MAKWA_BUFFER_TOO_SMALL is returned.
 * Otherwise, if the buffer is large enough, then the output is produced,
 * written in the 'out' buffer, and '*out_len' is set with the number of
 * bytes written into the output buffer. There again, for string output,
 * that length includes the terminating 0.
 *
 * Note that when the output is not written in the 'out' buffer, then the
 * production does not occur; thus, the function is fast. Therefore, the
 * normal usage pattern should be one of the followings:
 *
 * 1. Call the function twice; first call sets 'out' to NULL and 'out_len'
 *    to a pointer to a local variable, which receives the required buffer
 *    length. Then the buffer is allocated, and the function is called
 *    again, this time with the buffer, and still 'out_len' set to the
 *    same pointer:
 *
 *       void *out;
 *       size_t out_len;
 *
 *       if (some_function(NULL, &out_len) < 0) { ...(handle error) }
 *       out = malloc(out_len);
 *       if (some_function(out, &out_len) < 0) { ...(handle error) }
 *
 * 2. Call the function once, with 'out' set to a "large buffer" and
 *    'out_len' pointing to the length of that buffer:
 *
 *       unsigned char out[1024];
 *       size_t out_len;
 *
 *       out_len = sizeof out;
 *       if (some_function(out, &out_len) < 0) { ...(handle error) }
 *       // now out_len contains the actual output length
 *
 * 3. When the function output is known accurately in advance (e.g. Makwa
 *    is called with post-hashing applied to a definite output length),
 *    then call the function once with a properly sized output buffer,
 *    and set 'out_len' to NULL:
 *
 *       unsigned char out[42]; // the precomputed output size
 *
 *       if (some_function(out, NULL) < 0) { ...(handle error) }
 *
 * The third pattern is "simpler" but more bug-prone, because it implies
 * no check on the accuracy of the size precomputation.
 *
 * NOTES:
 *
 * -- The makwa_decode_string() function uses two output buffers. The
 * following extra semantics apply: both '*len' fields are set to the
 * predicted or actual length; if either of the buffers is too small
 * and would trigger a MAKWA_BUFFER_TOO_SMALL return value, then that
 * value is returned, but both '*len' fields are still set. Thus, one
 * call is sufficient to obtain both output lengths.
 *
 * -- A few functions may produce an output which is slightly smaller
 * than predicted. Therefore, when the two-call pattern is used, be sure
 * to use the same 'len' pointer for the second call, not NULL, and to
 * use that value as the length. These functions are duly documented as
 * such.
 */

/*
 * Symbolic constants for hash functions. Whenever such a constant is used,
 * 0 can also be used to select the "default function" (which is SHA-256).
 */
#define MAKWA_SHA256   1
#define MAKWA_SHA512   2

/*
 * Error codes.
 */
#define MAKWA_OK                  0  /* success */
#define MAKWA_WRONG_PASSWORD     -1  /* password hashed but no match */
#define MAKWA_NOMEM              -2  /* dynamic memory allocation failure */
#define MAKWA_BADPARAM           -3  /* invalid parameter value */
#define MAKWA_TOOLARGE           -4  /* value exceeds supported range */
#define MAKWA_BUFFER_TOO_SMALL   -5  /* output buffer is too small */
#define MAKWA_RAND_ERROR         -6  /* system PRNG failed */
#define MAKWA_HMAC_ERROR         -7  /* HMAC implementation failed */
#define MAKWA_NO_PRIVATE_KEY     -8  /* no known private key in context */
#define MAKWA_UNESCROW_ERROR     -9  /* unescrow failure */
#define MAKWA_PRE_HASH          -10  /* cannot operate: pre-hashing applied */
#define MAKWA_POST_HASH         -11  /* cannot operate: post-hashing applied */
#define MAKWA_EMBEDDED_ZERO     -12  /* escrowed password contains a zero */

/*
 * Run the Makwa internal KDF over the provided source and data bytes.
 * The 'hash_function' parameter is a symbolic constant which identifies
 * the hash function, e.g. MAKWA_SHA256 or MAKWA_SHA512. Use 0 to select
 * the default (which is SHA-256).
 *
 * NOTE: since the destination length is provided explicitly, this
 * function does not apply the "output buffer semantics" explained
 * above. 'src' (respectively 'dst') may be NULL only if 'src_len'
 * (respectively 'dst_len') is 0.
 */
int makwa_kdf(int hash_function,
	const void *src, size_t src_len,
	void *dst, size_t dst_len);

/*
 * A makwa_context is an opaque structure which contains the following
 * information:
 * -- the Makwa modulus or private key;
 * -- the hash function to use with the KDF;
 * -- whether pre-hashing should be applied (when calling one of the
 *    makwa_simple_*() functions);
 * -- whether post-hashing should be applied (when calling one of the
 *    makwa_simple_*() functions), and with what target output length;
 * -- the work factor to use when calling the makwa_simple_*() functions.
 *
 * An instance is created with makwa_new(), and released with makwa_free().
 * It is initialized with makwa_init() or makwa_init_full(). It is
 * possible to re-initialize an allocated structure by calling makwa_init()
 * or makwa_init_full() again. Once initialized, and until re-initialization
 * or release, a makwa_context instance is thread-safe.
 */
typedef struct makwa_context_ makwa_context;

/*
 * Create a new uninitialized makwa_context instance. On memory allocation
 * error, NULL is returned.
 */
makwa_context *makwa_new(void);

/*
 * Release a makwa_context instance; this also releases all resources
 * allocated from that context. If ctx is NULL, then this function does
 * nothing.
 */
void makwa_free(makwa_context *ctx);

/*
 * Initialize a makwa_context instance. This function is equivalent to
 * calling makwa_init_full(ctx, param, param_len, hash_function, 0, 0, 0).
 */
int makwa_init(makwa_context *ctx,
	const void *param, size_t param_len,
	int hash_function);

/*
 * Initialize a makwa_context instance.
 *
 *  ctx
 *    The context to initialize. It must have been created with makwa_new().
 *
 *  param
 *  param_len
 *    The encoded parameters (modulus or private key). A set of
 *    delegation parameters can also be used (only the modulus is
 *    extracted). The format follows what is descrived in the Makwa
 *    specification, section A.5.
 *
 *  hash_function
 *    The symbolic identifier for the hash function (used in the KDF). Use
 *    MAKWA_SHA256 for SHA-256, MAKWA_SHA512 for SHA-512. If this parameter
 *    is 0, then the default (SHA-256) is used.
 *
 *  default_pre_hash
 *    If non-zero, then pre-hashing will be applied when calling
 *    makwa_simple_hash_new().
 *
 *  default_post_hash_length
 *    If zero, then no post-hashing will be applied when calling
 *    makwa_simple_hash_new(). Otherwise, post-hashing is applied and
 *    will produce exactly that many bytes of binary output. If non-zero,
 *    then that parameter must have value 10 or more.
 *
 *  default_work_factor
 *    The work factor to apply when calling makwa_simple_hash_new(). If
 *    0, then a default work factor will be used (4096); otherwise, the
 *    work factor must be "encodable", i.e. equal to 2 or 3 multiplied
 *    by a power of 2.
 *
 * A given context structure can be reinitialized by calling this function
 * again. Between any two successive (re)initializations, a given context
 * structure is thread-safe.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_init_full(makwa_context *ctx,
	const void *param, size_t param_len,
	int hash_function,
	int default_pre_hash,
	size_t default_post_hash_length,
	long default_work_factor);

/*
 * Export the modulus that a provided initialized context uses. Note that
 * this always exports the modulus, not the private key, even if the
 * context was initialized with a private key. The out/out_len values
 * follow the "output buffer semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_export_public(const makwa_context *ctx, void *out, size_t *out_len);

/*
 * Create a new random salt. The provided buffer is filled with
 * pseudo-random bytes. If the buffer is large enough, then this ensures
 * salt uniqueness with overwhelming probability. The recommended salt
 * length is 16 bytes.
 *
 * This function does NOT claim to return randomness of cryptographic
 * quality. This is for salts, not keys.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_make_new_salt(void *salt, size_t salt_len);

/*
 * Compute a Makwa hash. The modulus (or private key) and the hash
 * function are obtained from the provided context; all other parameters
 * are provided explicitly:
 *
 *  input
 *  input_len
 *    The Makwa input: this is an arbitrary sequence of bytes. When
 *    the input is a password, applications should strive to encode
 *    the password in UTF-8.
 *
 *  salt
 *  salt_len
 *    The Makwa salt: an abritrary sequence of bytes.
 *
 *  pre_hash
 *    If non-zero, then pre-hashing will be applied.
 *
 *  post_hash_length
 *    If zero, then no post-hashing is applied, and the binary output
 *    will have the same length as the modulus. If non-zero, then
 *    post-hashing will be applied and produce exactly that many bytes.
 *    For this function, there is no constraint on this parameter.
 *
 *  work_factor
 *    The work factor is a nonnegative integer; this function does not
 *    otherwise constraint this parameter.
 *
 *  out
 *  out_len
 *    The buffer which receives the binary output, using the "output buffer
 *    semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_hash(const makwa_context *ctx,
	const void *input, size_t input_len,
	const void *salt, size_t salt_len,
	int pre_hash,
	size_t post_hash_length,
	long work_factor,
	void *out, size_t *out_len);

/*
 * Change the work factor for a given Makwa output. The provided buffer
 * must contain a Makwa primary output (no post-hashing) matching the
 * modulus used in 'ctx'; the new output replaces the old one in that
 * buffer. The difference between the new work factor and the old one is
 * given as 'diff_wf' parameter. A negative difference (work factor
 * decrease) is supported only if the context was initialized with a
 * private key.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_change_work_factor(const makwa_context *ctx,
	void *out, size_t out_len, long diff_wf);

/*
 * Unescrow a Makwa output. The provided buffer must contain a Makwa
 * primary output (no post-hashing) and no pre-hashing may have been
 * applied. The context must have been initialized with a private key.
 * The (nonnegative) work factor used to produce the Makwa output must
 * be provided as parameter.
 *
 * When calling this function, '*out_len' must contain the length
 * (in bytes) of the Makwa primary output currently stored in 'out'.
 *
 * Upon successful unescrow, the retrieved input is written in the 'out'
 * buffer, replacing the Makwa output; and the input length is written
 * in '*out_len'. The rest of the buffer is filled with zeros. Since the
 * escrowed input is always smaller than the Makwa primary output (by at
 * least 32 bytes), it is guaranteed that if the unescrowed value is
 * expected to be a character string, then it is zero-terminated in the
 * 'out' buffer.
 */
int makwa_unescrow(const makwa_context *ctx,
	const void *salt, size_t salt_len,
	long work_factor, void *out, size_t *out_len);

/*
 * Generate a new private key. The target modulus size (in bits)
 * is given as parameter; it must be between 1273 and 32768. The
 * key/key_len values follow the "output buffer semantics".
 *
 * Return value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_generate_key(int size, void *key, size_t *key_len);

/*
 * Compute a public key (modulus) from a private key. The mod/mod_len
 * values follow the "output buffer semantics".
 *
 * Return value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_compute_modulus(
	const void *key, size_t key_len, void *mod, size_t *mod_len);

/* ====================================================================== */
/*
 * Delegation API. When using delegation, the expensive part of a Makwa
 * computation can be delegated to an external untrusted system, deemed
 * the "delegation server".
 */

/*
 * A makwa_delegation_parameters structure contains a set of parameters
 * used for Makwa delegation. Such a structure is allocated with
 * makwa_delegation_new(), initialized with makwa_delegation_init(),
 * and released with makwa_delegation_free().
 *
 * This context is then used with makwa_hash_delegate_begin() and
 * makwa_hash_delegate_end().
 */
typedef struct makwa_delegation_parameters_ makwa_delegation_parameters;

/*
 * Generate a new set of delegation parameters, for a given modulus and
 * work factor. The "modulus" is provided as an encoded modulus, private
 * key, or other set of delegation parameters. The new set of delegation
 * parameters is written in out/out_len (with the "output buffer
 * semantics"); it follows the format specified in section A.5. Using a
 * private key is recommended, because it allows much faster
 * computations.
 *
 * WARNING: the predicted length (as returned in *out_len when out is
 * NULL or undersized) may turn out to be slightly larger than the
 * actual length. Therefore, when using the "output buffer semantics"
 * with the two-calls user pattern, be sure to always obtain the output
 * length from the second call as the final value.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_delegation_generate(const void *param, size_t param_len,
	long work_factor, void *out, size_t *out_len);

/*
 * Allocate a new makwa_delegation_parameters instance. On memory allocation
 * failure, NULL is returned.
 */
makwa_delegation_parameters *makwa_delegation_new(void);

/*
 * Release a makwa_delegation_parameters instance. If 'mdp' is NULL, then
 * this function does nothing.
 */
void makwa_delegation_free(makwa_delegation_parameters *mdp);

/*
 * Initialize a makwa_delegation_parameters instance by decoding it. The
 * provided byte sequence must match the format described in the
 * Makwa specification, section A.5.
 *
 * A makwa_delegation_parameters instance can be reinitialized several
 * times. Between two (re-)initializations, any given instance is
 * thread-safe (it can be used by several threads concurrently).
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_delegation_init(makwa_delegation_parameters *mdp,
	const void *param, size_t param_len);

/*
 * Get the work factor used in a given set of delegation parameters. The
 * 'mdp' instance can be used only for hashing with that exact work
 * factor.
 */
long makwa_delegation_get_work_factor(const makwa_delegation_parameters *mdp);

/*
 * A makwa_delegation_context instance maintains the running state of a
 * delegated hash computation. It is allocated with
 * makwa_delegation_context_new() and released with
 * makwa_delegation_context_free(). It is initialized with
 * makwa_hash_delegate_begin().
 *
 * Allocated instances can be reused for successive delegations.
 */
typedef struct makwa_delegation_context_ makwa_delegation_context;

/*
 * Allocate a new makwa_delegation_context instance. On memory allocation
 * failure, this function returns NULL.
 */
makwa_delegation_context *makwa_delegation_context_new(void);

/*
 * Release an allocated makwa_delegation_context instance. If 'mdc' is
 * NULL, then this function does nothing.
 */
void makwa_delegation_context_free(makwa_delegation_context *mdc);

/*
 * Initiate a Makwa delegated hash computation. The input, salt,
 * pre-hashing flag and post-hashing length are provided. The work
 * factor is extracted from the makwa_delegation_parameters instance.
 * The modulus and hash function come from the makwa_context. The
 * makwa_delegation_context instance 'mdc' is filled with the
 * state for this function.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_hash_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	const void *input, size_t input_len,
	const void *salt, size_t salt_len,
	int pre_hash, size_t post_hash_length,
	makwa_delegation_context *mdc);

/*
 * Encode a delegation request into bytes. The req/req_len parameters
 * use the "output buffer semantics".
 *
 * WARNING: the predicted length (as returned in *req_len when req is
 * NULL or undersized) may turn out to be slightly larger than the
 * actual length. Therefore, when using the "output buffer semantics"
 * with the two-calls user pattern, be sure to always obtain the output
 * length from the second call as the final value.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_delegation_context_encode(
	const makwa_delegation_context *mdc, void *req, size_t *req_len);

/*
 * Decode a delegation request, process it, and encode the answer. The
 * ans/ans_len parameters use the "output buffer semantics". This
 * function is what the delegation server uses; note that it works without
 * any context.
 *
 * WARNING: the predicted length (as returned in *ans_len when ans is
 * NULL or undersized) may turn out to be slightly larger than the
 * actual length. Therefore, when using the "output buffer semantics"
 * with the two-calls user pattern, be sure to always obtain the output
 * length from the second call as the final value.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_delegation_answer(
	const void *req, size_t req_len, void *ans, size_t *ans_len);

/*
 * Finalize a Makwa delegated hash computation with the response from
 * the delegation server (ans/ans_len).
 *
 * The out/out_len parameters receive the hash result; they use the
 * "output buffer semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_hash_delegate_end(const makwa_delegation_context *mdc,
	const void *ans, size_t ans_len,
	void *out, size_t *out_len);

/* ====================================================================== */
/*
 * The "simple" API consists in functions which encode Makwa output as
 * strings, as described in section A.4 of the Makwa specification.
 * Such a string contains:
 *
 * -- A checksum computed over the modulus with the internal KDF. it
 * characterizes both the modulus and the hash function, and is meant to
 * detect accidental misconfigurations.
 * -- The pre-hashing and post-hashing flags.
 * -- The work factor.
 * -- The salt.
 * -- The binary Makwa output itself.
 *
 * This encoding thus aggregates multiple parameters into a single ASCII
 * string, which can be handled by string-based storage mechanisms. The
 * API is simpler than the generic API presented above. It implies,
 * though, some extra constraints:
 * -- If post-hashing is used, then the post-hashing length MUST be at
 * least 10 bytes.
 * -- The work factor must be "encodable", meaning that it must be equal
 * to 2 or 3 times a power of 2.
 */

/*
 * When encoding the Makwa output as a string, this function returns
 * the string length, in characters, including the terminating zero.
 * The 'post_hash_length' parameter is 0 (no post-hashing), or the
 * target binary output length in bytes (must be 10 or more).
 */
size_t makwa_get_string_output_length(
	const makwa_context *ctx, size_t salt_len, size_t post_hash_length);

/*
 * Encode a Makwa output into a string. See makwa_hash() for most
 * parameters; however, this function does NOT compute Makwa itself;
 * the binary output which is to be encoded must be provided explicitly
 * as the bin_out parameter. The length of that Makwa output is inferred
 * from the parameters.
 *
 * The work factor must be encodable: equal to 2 or 3 times a power of 2.
 * The post-hashing length, if non-zero, must be 10 or more. Failure to
 * meet these constraints results in a MAKWA_BADPARAM error code.
 *
 * The 'str_out' and 'str_out_len' use the "output buffer semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_encode_string(const makwa_context *ctx,
	const void *salt, size_t salt_len,
	int pre_hash,
	size_t post_hash_length,
	long work_factor,
	const void *bin_out,
	char *str_out, size_t *str_out_len);

/*
 * Decode a Makwa output string ('str'). The context is used to verify the
 * string against the known modulus or private key; on mismatch,
 * MAKWA_BADPARAM is returned. The salt, pre-hashing flag, post-hashing
 * length (or 0), work factor and binary output are extracted. Both
 * salt/salt_len and out/out_len follow the "output buffer semantics".
 *
 * Note that if one buffer is too small (MAKWA_BUFFER_TOO_SMALL returned)
 * then both '*salt_len' and '*out_len' are still adjusted to the required
 * lengths.
 *
 * 'pre_hash', 'post_hash_length' and 'work_factor' may be NULL if the
 * caller is not interested in these values.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_decode_string(const makwa_context *ctx,
	const char *str,
	void *salt, size_t *salt_len,
	int *pre_hash,
	size_t *post_hash_length,
	long *work_factor,
	void *out, size_t *out_len);

/*
 * Hash a password. The default parameters used to initialize 'ctx' are
 * used. A new salt is internally generated (of length 16 bytes). The
 * password must be a zero-terminated string, and should normally be
 * UTF-8 encoded (a non-UTF-8 password will be processed nonetheless, but
 * UTF-8 is the convention which maximizes interoperability).
 *
 * The 'str_out' and 'str_out_len' use the "output buffer semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_hash_new(const makwa_context *ctx,
	const char *password, char *str_out, size_t *str_out_len);

/*
 * Hash a password for verification. The modulus (or private key) and
 * hash function from 'ctx' are used; the other hashing parameters (salt,
 * pre-hashing, post-hashing, work factor) are extracted by decoding the
 * provided reference string (ref_str, a string-encoded Makwa output).
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 * If all the decoding and hashing went well, which implies that the
 * reference string was syntactically correct and indeed used the modulus
 * and hash function from 'ctx', but the password turned out to be the
 * wrong one (a different binary output is generated), then the returned
 * value is MAKWA_WRONG_PASSWORD.
 */
int makwa_simple_hash_verify(const makwa_context *ctx,
	const char *password, const char *ref_str);

/*
 * Set the work factor to a new value. The provided string 'str' is
 * modified in place; the new string has the same length.
 *
 * A work factor decrease (new work factor is lower than the one in
 * the string) is possible only if the context was initialized with a
 * private key.
 *
 * Note that this function takes as last parameter the new work factor,
 * _not_ the difference with the previous work factor.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_reset_work_factor(const makwa_context *ctx,
	char *str, long new_work_factor);

/*
 * Unescrow the password from a Makwa output (string-encoded). The
 * provided 'str' is modified in place; the unescrowed password is
 * necessarily shorter than the source string. The remaining of the
 * 'str' buffer (up to its initial terminating 0) is filled with
 * zeros, so the unescrowed password is zero terminated.
 *
 * 'str' is unmodified unless a success (MAKWA_OK) is reported. If
 * the unescrowed password turns out to contain an embedded byte of
 * value 0, then a MAKWA_EMBEDDED_ZERO error is returned.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_unescrow(const makwa_context *ctx, char *str);

/*
 * Begin a delegated hash for a new password; a random salt is internally
 * generated. The initialization parameters from the makwa_context instance
 * are used, except the default work factor, for which the value from the
 * makwa_delegation_parameters instance is used. That value must be
 * "encodable" (2 or 3 times a power of 2).
 *
 * The provided makwa_delegation_context instance is filled with the
 * parameters needed to complete the computation.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_hash_new_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	char *password, makwa_delegation_context *mdc);

/*
 * Begin a delegated hash for a password verification; the parameters
 * are extracted from the provided reference string. The delegation
 * parameters must match the used work factor.
 *
 * The provided makwa_delegation_context instance is filled with the
 * parameters needed to complete the computation.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_hash_verify_delegate_begin(const makwa_context *ctx,
	const makwa_delegation_parameters *mdp,
	char *password, const char *ref, makwa_delegation_context *mdc);

/*
 * Complete a delegated hash computation; the hash value is produced and
 * encoded as a string. The str_out/str_out_len values use the "output
 * buffer semantics".
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code.
 */
int makwa_simple_hash_delegate_end(const makwa_delegation_context *mdc,
	const void *ans, size_t ans_len, void *str_out, size_t *str_out_len);

/*
 * Complete a delegated hash computation; this function may be called if the
 * hash computation was started with makwa_simple_hash_verify_delegate_begin()
 * and thus the context already contains the output to compare with.
 *
 * Returned value is 0 (MAKWA_OK) on success, or a negative error code. If
 * everything went well but the output does not match, then a
 * MAKWA_WRONG_PASSWORD error code is returned.
 */
int makwa_simple_hash_verify_delegate_end(
	const makwa_delegation_context *mdc, const void *ans, size_t ans_len);

/* ====================================================================== */
/*
 * API for the PHC (Password Hashing Competition).
 *
 * The PHC call for submissions states that the reference C code shall
 * provide a function named PHS() with the prototype below. Such a
 * function is thus included.
 *
 * DO NOT USE THIS FUNCTION. Its behaviour is the following: it calls
 * Makwa with hard-coded parameters, in particular a 2048-bit modulus. I
 * generated that modulus myself. I did not keep the private key;
 * however, you will have to trust me for that. You should not trust me
 * (I wouldn't). Besides, lack of private key, and systematic use of
 * pre-hashing and post-hashing, prevent application of all the nice
 * advanced features of Makwa (offline work factor increase, fast path,
 * unescrow...).
 *
 * The binary input in/inlen is hashed with salt salt/saltlen, and the
 * output is written int out/outlen (exactly outlen bytes are produced).
 * THe 't_cost' value is used as work factor; 'm_cost' is ignored. On
 * success, this function returns 0; otherwise, it returns a negative
 * error code.
 */
int PHS(void *out, size_t outlen,
	const void *in, size_t inlen, 
	const void *salt, size_t saltlen,
	unsigned int t_cost, unsigned int m_cost);

#endif
