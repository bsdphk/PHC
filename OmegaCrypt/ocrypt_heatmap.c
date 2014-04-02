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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <math.h>

#include "phs.h"

#define DW 12
#define DH 12

/* Generate a "heatmap" of memory and time usage for various parameters */

int main(void) {

  int i, j;
  int time[DH][DW];
  clock_t start, diff;
  int64_t min = -1;
  int64_t max = -1;
  int ret;
  uint8_t hash[64];
  double tscale, tscalel;

  printf("P3\n");
  printf("%d %d\n", DW, DH);
  printf("255\n");

  for (i = 0; i < DH; i++) {
    for (j = 0; j < DW; j++) {
      start = clock();
      ret = PHS(hash, 64, NULL, 0, NULL, 0, i, j);
      (void)ret;
      diff = clock() - start;

      if ((min == -1) ||
	  (diff < min)) {
	min = diff;
      }
      if (diff > max) {
	max = diff;
      }

      time[i][j] = diff;
    }
  }

  for (i = DH - 1; i >= 0; i--) {
    for (j = 0; j < DW; j++) {
      fprintf(stderr, "%d ", time[i][j]);
    }
    fprintf(stderr, "\n");
  }

  tscalel = 255.0 / (log2(max) - log2(min));
  tscale = 255.0 / (max - min);
  for (i = DH - 1; i >= 0; i--) {
    for (j = 0; j < DW; j++) {
      printf("%ld %ld %ld ", lround((double)j * (255.0 / (DW - 1))),
	     lround((log2((double)time[i][j]) - log2(min)) * tscalel),
	     lround((((double)time[i][j]) - min) * tscale));
    }
    printf("\n");
  }
  

  return 0;
}
