#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "catena.h"

void print_hex(const char *message, const uint8_t *x, const int len)
{
  int i;
  puts(message);
    for(i=0; i< len; i++)
      {
	if((i!=0) && (i%8 == 0)) puts("");
	printf("%02x ",x[i]);
      }
    printf("     %d (octets)\n\n", len);
}

/*******************************************************************/

void test_output(const uint8_t *pwd,   const uint32_t pwdlen,
		 const uint8_t *salt,  const uint8_t saltlen,
		 const uint8_t *data,  const uint32_t datalen,
		 const uint8_t garlic, const uint8_t hashlen)
{
  uint8_t hash[hashlen];

  Catena(pwd, pwdlen, salt, saltlen, data, datalen,
	 LAMBDA, garlic, garlic, hashlen, hash);

  print_hex("Password: ",pwd, pwdlen);
  print_hex("Salt: ",salt, saltlen);
  print_hex("Associated data:", data, datalen);
  printf("Lambda:  %u\n",LAMBDA);
  printf("(Min-)Garlic:  %u\n",garlic);
  print_hex("\nOutput: ", hash, hashlen);
  puts("\n\n");
}


/*******************************************************************/

void simpletest(const char *password, const char *salt, const char *header,
		uint8_t garlic)
{
  test_output((uint8_t *) password, strlen(password),
	      (uint8_t *) salt,     strlen(salt),
	      (uint8_t *) header,   strlen(header), garlic, H_LEN);
}

/*******************************************************************/

void PHC_test()
{
  int i;
  uint8_t j = 0;

  for(i=0; i< 256; i++)test_output((uint8_t *) &i, 1, &j, 1, NULL ,0, 10, 32);
  for(i=0; i< 256; i++)test_output(&j, 1, (uint8_t *) &i, 1, NULL ,0, 10, 32);
}

/*******************************************************************/

int main()
{
  simpletest("password", "salt", "", 1);
  simpletest("password", "salt", "", 10);
  simpletest("password", "salt", "data", 10);

  simpletest("passwordPASSWORDpassword",
	     "saltSALTsaltSALTsaltSALTsaltSALTsalt","", 10);


  PHC_test();

  return 0;
}
