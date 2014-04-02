#include <stdio.h>
#include <stdlib.h>

#include "cubehash.h"


int main(void) {

  int i;

  uint8_t hash[CHASHSTATESIZE];
  char message[100] = "The quick brown fox jumps over the lazy dog";
 
  chash_message(160, 16, 32, 160, 512, (uint8_t *)message, 43, &hash);
  
  printf("The hash for \"%s\":\n", message);
  for (i = 0; i < (512 / 8); i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  return 0;
}
