#include "cubehash.h"

void chash_init(struct cubehash_ctx *cctx,
		int in, int r, int b, int f, int h) {

  int i, j, k, l, m;

  /* a parameter i in {1,2,3,...}, ... initialization rounds (16);
   * a parameter r in {1,2,3,...}, ... rounds per message block, (16);
   * a parameter b in {1,2,3,...,128}, ... bytes per message block, (32);
   * a parameter f in {1,2,3,...}, ... finalization rounds, (32);
   * a parameter h in {8,16,24,...,512}, ... output bits, (512); 
   */

  cctx->i = in;
  cctx->r = r;
  cctx->b = b;
  cctx->f = f;
  cctx->h = h;

  /* CubeHash produces the initial state as follows.
   * Set the first three state words x[00000], x[00001], x[00010] to the
   * integers h/8, b, r respectively. Set the remaining state words to 0.
   */
  for (i = 0; i < 2; i++) {
    for (j = 0; j < 2; j++) {
      for (k = 0; k < 2; k++) {
	for (l = 0; l < 2; l++) {
	  for (m = 0; m < 2; m++) {
	    cctx->state[i][j][k][l][m] = 0;
	  }
	}
      }
    }
  }

  cctx->state[0][0][0][0][0] = cctx->h / 8;
  cctx->state[0][0][0][0][1] = cctx->b;
  cctx->state[0][0][0][1][0] = cctx->r;

  /* Then transform the state invertibly through i rounds.
   * Of course, the implementor can eliminate these transformations
   * at the expense of storage by precomputing the initial state
   * for any particular h,b,r.
   */
  for (i = 0; i < cctx->i; i++) {
    chash_round(cctx);
  }

}


void chash_round(struct cubehash_ctx *cctx) {

  int j, k, l, m;
  uint32_t t;

  /* Add x[0jklm] into x[1jklm] modulo 2^32, for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[1][j][k][l][m] += cctx->state[0][j][k][l][m];
	}
      }
    }
  }

  /*Rotate x[0jklm] upwards by 7 bits, for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[0][j][k][l][m] =
	    ROTATEUPWARDSN(cctx->state[0][j][k][l][m], 7);
	}
      }
    }
  }

  /* Swap x[00klm] with x[01klm], for each (k,l,m). */
  for (k = 0; k < 2; k++) {
    for (l = 0; l < 2; l++) {
      for (m = 0; m < 2; m++) {
	WSWAP(cctx->state[0][0][k][l][m], cctx->state[0][1][k][l][m], t);
      }
    }
  }

  /* Xor x[1jklm] into x[0jklm], for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[0][j][k][l][m] ^= cctx->state[1][j][k][l][m];
	}
      }
    }
  }

  /* Swap x[1jk0m] with x[1jk1m], for each (j,k,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (m = 0; m < 2; m++) {
	WSWAP(cctx->state[1][j][k][0][m], cctx->state[1][j][k][1][m], t);
      }
    }
  }

  /* Add x[0jklm] into x[1jklm] modulo 2^32, for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[1][j][k][l][m] += cctx->state[0][j][k][l][m];
	}
      }
    }
  }

  /* Rotate x[0jklm] upwards by 11 bits, for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[0][j][k][l][m] =
	    ROTATEUPWARDSN(cctx->state[0][j][k][l][m], 11);
	}
      }
    }
  }

  /* Swap x[0j0lm] with x[0j1lm], for each (j,l,m). */
  for (j = 0; j < 2; j++) {
    for (l = 0; l < 2; l++) {
      for (m = 0; m < 2; m++) {
	WSWAP(cctx->state[0][j][0][l][m], cctx->state[0][j][1][l][m], t);
      }
    }
  }

  /* Xor x[1jklm] into x[0jklm], for each (j,k,l,m). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	for (m = 0; m < 2; m++) {
	  cctx->state[0][j][k][l][m] ^= cctx->state[1][j][k][l][m];
	}
      }
    }
  }


  /* Swap x[1jkl0] with x[1jkl1], for each (j,k,l). */
  for (j = 0; j < 2; j++) {
    for (k = 0; k < 2; k++) {
      for (l = 0; l < 2; l++) {
	WSWAP(cctx->state[1][j][k][l][0], cctx->state[1][j][k][l][1], t);
      }
    }
  }

}


void chash_update(struct cubehash_ctx *cctx, uint8_t (*in)[CHASHSTATESIZE]) {

  int i, j, k, l, m, b, r;
  int idx = 0;
  
  for (i = 0; i < 2; i++) {
    for (j = 0; j < 2; j++) {
      for (k = 0; k < 2; k++) {
	for (l = 0; l < 2; l++) {
	  for (m = 0; m < 2; m++) {
	    for (b = 0; b < 4; b++) {

	      /* XOR in the bytes starting low */
	      cctx->state[i][j][k][l][m] ^= (uint32_t)(*in)[idx] << (b * 8);
	      idx++;

	      /* If we've XOR'd in a whole block so finish */
	      if (idx >= cctx->b) {
		
		for (r = 0; r < cctx->r; r++) {
		  chash_round(cctx);
		}

		return;
	      }
	    }
	  }
	}
      }
    }
  }  

}


void chash_final(struct cubehash_ctx *cctx, uint8_t (*out)[CHASHSTATESIZE]) {

  int i, j, k, l, m, b, f;
  int idx;

  cctx->state[1][1][1][1][1] ^= 1;
  for (f = 0; f < cctx->f; f++) {
    chash_round(cctx);
  }

  idx = 0;
  for (i = 0; i < 2; i++) {
    for (j = 0; j < 2; j++) {
      for (k = 0; k < 2; k++) {
	for (l = 0; l < 2; l++) {
	  for (m = 0; m < 2; m++) {
	    for (b = 0; b < 4; b++) {
	      /* Extract out the state */
	      (*out)[idx] = (cctx->state[i][j][k][l][m] >> (b * 8)) & 0xff;
	      idx++;

	      /* If we've output the whole hash */
	      if (idx >= cctx->h / 8) {

		return;
	      }

	    }
	  }
	}
      }
    }
  }

}


void chash_message(int in, int r, int b, int f, int h,
		   uint8_t *m, size_t s, uint8_t (*hash)[CHASHSTATESIZE]) {

  struct cubehash_ctx cctx;
  uint8_t block[CHASHSTATESIZE];
  int i, j;

  chash_init(&cctx, in, r, b, f, h);
  
  /* Loop to consume message input in blocks */
  i = 0;
  while (1) {

    /* Still doing blocks? */
    if (i + cctx.b <= s) {
      memcpy(block, m + i, cctx.b);
      chash_update(&cctx, (uint8_t (*)[CHASHSTATESIZE])block);

      i += cctx.b; /* move down a block */
      continue;
    }
    else {
      /* We need to add the pad for the last block */
      for (j = 0; j < cctx.b; j++) {
	/* keep copying remaning message? */
	if (i < s) {
	  block[j] = m[i];
	  i++;
	  continue;
	}
	else if (i == s) {
	  /* Add the 1-bit pad */
	  block[j] = 0x80;
	  i++;
	  continue;
	}
	else {
	  /* Add zero bit pads */
	  block[j] = 0x00;
	}
      }
      chash_update(&cctx, (uint8_t (*)[CHASHSTATESIZE])block);

      break;
    }
  }

  chash_final(&cctx, hash);
}


