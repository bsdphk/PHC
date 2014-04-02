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

#include "phs.h"


void print_KAT(void *out, size_t outlen, const void *in, size_t inlen,
	       const void *salt, size_t saltlen, unsigned int t_cost,
	       unsigned int m_cost, int ascii) {

  int i, ret;

  printf("\n");
  printf("Msg Len = %ld\n", inlen);
  printf("Msg = ");
  for (i = 0; i < inlen; i++) {
    printf("%02x", ((uint8_t *)in)[i]);
  }
  printf("\n");
  if (ascii == 1) {
    printf("Msg ASCII = %s\n", (const char *)in);
  }

  printf("Salt Len = %ld\n", saltlen);
  printf("Salt = ");
  for (i = 0; i < saltlen; i++) {
    printf("%02x", ((uint8_t *)salt)[i]);
  }
  printf("\n");

  printf("Key Len = %d\n", 0);
  printf("Key = \n");

  printf("t_cost = %d\n", t_cost);
  printf("m_cost = %d\n", m_cost);

  printf("Out Len = %ld\n", outlen);
  printf("Out = ");
  ret = PHS(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost);
  (void)ret;


  for (i = 0; i < outlen; i++) {
    printf("%02x", ((uint8_t *)out)[i]);
  }
  printf("\n");


}


int main(void) {

  char *pass[] = {"", "123456", "password", "qwerty", "Hello",
		   "The quick brown fox jumps over the lazy dog"};
  size_t plen;
  uint8_t hash[64];
  uint8_t salt[16];


  int i, j;


  printf("# Known Answer Test (KAT)\n");
  printf("# Algorithm Name: Omega Crypt (ocrypt)\n");
  printf("# Principle Submitter: "
	 "Brandon Enright <bmenrigh@brandonenright.net>\n");
  printf("# Password Hashing Competition -- https://password-hashing.net/\n");


  /* Some common input */
  for (i = 0; i < 6; i++) {
    plen = strlen((const char *)pass[i]);
    print_KAT(hash, 16, pass[i], plen, NULL, 0, 0, 0, 1);
    print_KAT(hash, 32, pass[i], plen, NULL, 0, 0, 0, 1);
    print_KAT(hash, 64, pass[i], plen, NULL, 0, 0, 0, 1);
  }

  /* 0 .. 255 as input, 128-bit all-zero salt */
  memset(salt, 0, 16);
  for (i = 0; i < 256; i++) {
    print_KAT(hash, 64, &i, 1, salt, 16, 0, 0, 0);
  }

  /* 0x15 + 0 .. 255 as salt, null input */
  memset(salt, 0, 16);
  for (i = 0; i < 256; i++) {
    salt[15] = i;
    print_KAT(hash, 64, NULL, 0, salt, 16, 0, 0, 0);
  }

  /* For m and t costs 0 .. 7 */
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 8; j++) {
      print_KAT(hash, 64, NULL, 0, NULL, 0, i, j, 0);
    }
  }

  return 0;
}
