/*  Authored by Jeremi Gosney, 2014
    Placed in the public domain.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../common/common.h"
#include "../common/itoa64.h"
#include "../common/api.h"

#ifdef OPTIMIZED
  #include "../optimized/pufferfish.h"
#else
  #include <openssl/sha.h>
  #include <openssl/hmac.h>
  #include "../reference/pufferfish.h"
#endif

int main (int argc, char **argv)
{
	unsigned int i, bits = 0, raw = 0, t_cost = 6, m_cost = 10;
	char password[255] = { 0 };
	unsigned char *key;
	char *tmp;

	if (argc < 2)
	{
		fprintf (stderr, "Usage: %s [bits] <raw> <t_cost> <m_cost>\n", argv[0]);
		fprintf (stderr, "    bits   -  number of bits to derive. required.\n");
		fprintf (stderr, "    raw    -  0 (default) for hex, or 1 for raw bytes. optional.\n");
		fprintf (stderr, "    t_cost -  number of log2 iterations. default 6. optional.\n");
		fprintf (stderr, "    m_cost -  number of log2 memory to use. default 10. optional.\n\n");
		return 1;
	}

	while (1)
	{
		tmp = getpass ("Password: ");
		memmove (password, tmp, strlen (tmp));
		tmp = getpass ("Re-enter password: ");

		if ((strlen (password) == strlen (tmp)) && (! strncmp (password, tmp, strlen (password))))
			break;

		fprintf (stderr, "Passwords do not match.\n\n");
		memset (password, 0, 255);
		sleep (1);
	}

	bits = atoi (argv[1]);

	if (argc > 2) raw = atoi (argv[2]);
	if (argc > 3) t_cost = atoi (argv[3]);
	if (argc > 4) m_cost = atoi (argv[4]);


	key = pfkdf (bits, password, t_cost, m_cost);
		
	if (!raw)
	{
		printf ("\n");
		for (i=0; i < bits / 8; i++)
			printf ("%02x ", key[i]);
		printf ("\n\n");
	}
	else
	{
		for (i=0; i < bits / 8; i++)
			printf ("%c", key[i]);
	}

	fflush(stdout);

	free (tmp);
	free (key);

	memset (password, 0, 255);

	return 0;
}
