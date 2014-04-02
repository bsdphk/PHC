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
	unsigned int t_cost = 0, m_cost = 0, saltlen = 16;
	char *tmp, *settings, *hash, *salt = NULL;
	char password[255] = { 0 };
	int valid = 1;

	if (argc < 3)
	{
		fprintf (stderr, "Usage: %s [t_cost] [m_cost] <salt> \n", argv[0]);
		return 1;
	}

	while (1)
	{
		tmp = getpass ("Password: ");
		memmove (password, tmp, strlen(tmp));
		tmp = getpass ("Re-enter password: ");

		if ((strlen (password) == strlen (tmp)) && (! strncmp (password, tmp, strlen (password))))
			break;

		fprintf (stderr, "Passwords do not match.\n\n");
		memset (password, 0, 255);
		sleep (1);
	}

	t_cost = atoi (argv[1]);
	m_cost = atoi (argv[2]);

	if (argc == 4)
	{
		salt = argv[3];
		saltlen = strlen (argv[3]);
	}

	settings = pf_gensalt ((const unsigned char *) salt, saltlen, t_cost, m_cost);
	hash = pufferfish (password, strlen (password), settings, 32, false);
	valid = pufferfish_validate (password, hash);

	printf ("\n%s\n\n", hash);

	free (settings);
	free (hash);
	free (tmp);

	if (argc != 4)
		free (salt);

	memset (password, 0, 255);

	return valid;
}
