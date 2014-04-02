#ifndef _PHC_DEBUG_H
	#define _PHC_DEBUG_H

	/* **************************************************
	 * Debug-only macros
	 *
	 * These macros are removed by the optimization step
	 * in case DEBUG is not set...
	 * *************************************************/
	#ifdef PHC_DEBUG_OUTPUT
		#define Dprintf(...) do { \
			printf(__VA_ARGS__);  \
		} while(0)

		#define DprintMemory(mem, size) do { \
			uint8_t *_dbg_MemPtr = (uint8_t*) mem; \
			for (int _dbg_i = 0; _dbg_i < size; _dbg_i ++) { \
				printf("%02" PRIx8, _dbg_MemPtr[_dbg_i] );            \
				if ((_dbg_i % 4) == 3 ) {                               \
					printf(" ");                                        \
				}                                                       \
				if ((_dbg_i % 32) == 31) {                              \
					printf("\n");                                       \
				} \
			} \
			if ((size % 32) != 0) { \
				printf("\n"); \
			} \
		} while (0)
				
		#define DprintFullState(ctx) do {                                   \
			Dprintf("Full State  :\n"); \
			DprintMemory(ctx->stateprefix, ctx->state_bytes+sizeof(uint32_t)); \
		} while(0)

		#define DprintRehashState(ctx) do {                                   \
			Dprintf("Rehash State:\n"); \
			DprintMemory(ctx->rehashprefix, PHS_REHASH_SIZE); \
		} while(0)
	#else
		#define Dprintf(...) do { } while(0)
		#define DprintMemory(mem, size) do { } while(0)
		#define DprintFullState(ctx) do { } while(0)
		#define DprintRehashState(ctx) do { } while(0)
	#endif

#endif	
