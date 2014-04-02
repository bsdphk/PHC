/* Some descriptions ...
 *
 *
 */
#ifndef _PHC_H
	#define _PHC_H
	
	/* Helper macros */
	#define ROTR(X,N)  (((X) >> (N)) | ((X) << (32-(N))))

	/* **************************************************
	 * Constant return codes for PHS function
	 * *************************************************/
	#define PHS_SUCCESS          (  0 )
	#define PHS_INVALID_MCOST    ( -1 )
	#define PHS_INVALID_PCOST    ( -2 )
	#define PHS_INVALID_SALT     ( -3 )
	#define PHS_INVALID_PASSWORD ( -4 )

	/* **************************************************
	 * Constants for the PHS functions
	 * **************************************************/

	/* Fixed-width salt size in bytes */
	#define PHS_SALT_SIZE   (16)
	/* Fixed-width hash output size in bytes.
	 * Note: this needs to be adjusted for different hash functions!
	 */
	#define PHS_HASH_SIZE   (64)
	#define PHS_REHASH_SIZE (PHS_HASH_SIZE + sizeof(uint32_t)) 
	/* used in normal operations */
	#define PHS_F_ADD   (0x01234567)
	#define PHS_F_XOR   (0x01234567)
	#define PHS_F_MUL   (0x89ABCDEF)
	#define PHS_F_AND   (0xFEFEFEFE)
	#define PHS_F_OR    (0x02020202)
	#define PHS_F_SHL   (3)
	#define PHS_F_ROTR  (7)
	/* used in floating point operations */
	#define PHS_F_FP_31 2147483648.L
	#define PHS_F_FP_32 4294967296.L
	#define PHS_F_FP_C0 1000000000.L
	#define PHS_F_FP_C1 5000000000.L

	/* **************************************************
	 * Definition of multiple fast (CPU) functions
	 * *************************************************/
	/* number of functions */
	#define PHS_F_COUNT     (10)
	/* integer operations */
	#define F00(X) ( (X) + PHS_F_ADD )
	#define F01(X) ( (X) * PHS_F_MUL )
	/* bit operations */
	#define F02(X) ( (X) >> PHS_F_SHL )
	#define F03(X) ( ROTR((X), PHS_F_ROTR) )
	#define F04(X) ( (X) ^ PHS_F_XOR )
	#define F05(X) ( (X) & PHS_F_AND )
	#define F06(X) ( (X) | PHS_F_OR )
	/* floating point operations */
	#define F07(X) ( (uint32_t) ( PHS_F_FP_31 * sin (((double) X)/PHS_F_FP_C0 )) )
	#define F08(X) ( (uint32_t) ( PHS_F_FP_31 * cos (((double) X)/PHS_F_FP_C0 )) )
	#define F09(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )
	/* 1/x: [1,2] -> [0.5, 1] (bijective) */
	#define F10(X) ( (uint32_t) ( (double) ( 2 * PHS_F_FP_32 * ( 1 / (1.5 + (double) X / PHS_F_FP_32 )) - 0.75 ) ) )
	/* dummy functions, unused and not called */
	#define F11(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )
	#define F12(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )
	#define F13(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )
	#define F14(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )
	#define F15(X) ( (uint32_t) ( PHS_F_FP_31 * tan (((double) X)/PHS_F_FP_C1 )) )

	/* **************************************************
	 * Type definitions
	 * *************************************************/

	/* the context strucure stores the relevant data during the execution */
	typedef struct td_phs_ctx_t {
		uint32_t *stateprefix;  /* 32-bit counter value as prefix for output generation */
		void     *state;        /* buffer for the full state = [32-bit cnt] | [state] */
		uint32_t *rehashprefix; /* 32-bit counter value as prefix for rehashing */ 
		void     *rehash;       /* buffer for rehashing = [32-bit cnt] | [hash]*/
		uint32_t state_bytes;   /* length of state in bytes */
		uint32_t state_words;   /* length of state in 32-bit words */
		uint32_t outer_rounds;  /* number of outer rounds */
		uint32_t inner_rounds;  /* number of inner rounds */
	} phs_ctx_t;


	/* **************************************************
	 * Function prototypes
	 * *************************************************/
	/* required API call */
	int PHS(void*, size_t, const void*, size_t, const void*, size_t, unsigned int, unsigned int);
	/* F function */
	uint32_t F(uint8_t, uint32_t);
	/* initialization of the context */
	void phs_init(phs_ctx_t*, const uint8_t*, const uint8_t*, size_t);
	/* re-distribution of the entropy on the state */
	void phs_upd_entropy(phs_ctx_t*);
	/* update the state using the F function */
	void phs_upd_state(phs_ctx_t*);
	/* derive new state from rehash buffer */
	void phs_store_derive_state(phs_ctx_t *);

#endif // _PHC_H
