#ifndef CUBEHASH_H
#define CUBEHASH_H

#include <string.h>
#include <stdint.h>

#define CHASHSTATESIZE 128
#define ROTATEUPWARDSN(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define WSWAP(a, b, t) {t = a; a = b; b = t;}


/* Cubehash Context */
struct cubehash_ctx {
  uint32_t state[2][2][2][2][2];
  int i, r, b, f, h;
};


void chash_init(struct cubehash_ctx *, int, int, int, int, int);
void chash_round(struct cubehash_ctx *);
void chash_update(struct cubehash_ctx *, uint8_t (*)[CHASHSTATESIZE]);
void chash_final(struct cubehash_ctx *, uint8_t (*)[CHASHSTATESIZE]);
void chash_message(int, int, int, int, int, uint8_t *, size_t,
		   uint8_t (*)[CHASHSTATESIZE]);

#endif
