/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

/*
 * This command-line tool generates a new public/private key pair. The
 * public modulus, and/or the private key, can be optionally written to
 * a dik file. The modulus can also be written out on the console
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "makwa.h"

static void
fail(char *fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "FAIL: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	abort();
}

#define CF(x)   do { \
		int error_code = (x); \
		if (error_code < 0) { \
			fail("line %ld: %s returned %d\n", \
				(long)__LINE__, #x, error_code); \
			abort(); \
		} \
	} while (0)

static void *
xmalloc(size_t len)
{
	void *x;

	if (len == 0) {
		return NULL;
	}
	x = malloc(len);
	if (x == NULL) {
		fail("memory allocation failure: %lu bytes\n",
			(unsigned long)len);
	}
	return x;
}

static void
xfree(void *x)
{
	if (x != NULL) {
		free(x);
	}
}

static void
usage(void)
{
	fprintf(stderr,
"usage: keygen size [ -text ] [ -outpub file ] [ -outpriv file ]\n");
	exit(EXIT_FAILURE);
}

static void
write_file(char *name, const void *data, size_t data_len)
{
	FILE *f;

	f = fopen(name, "wb");
	if (f == NULL) {
		fail("could not open file '%s' for writing", name);
	}
	if (fwrite(data, 1, data_len, f) != data_len) {
		fail("short write in file '%s': %lu bytes",
			name, (unsigned long)data_len);
	}
	fclose(f);
}

int
main(int argc, char *argv[])
{
	char *outpub, *outpriv;
	int text;
	int i;
	int size;
	unsigned char *priv, *pub;
	size_t priv_len, pub_len;

	/* Parse command-line arguments. */
	text = 0;
	outpub = NULL;
	outpriv = NULL;
	size = 0;
	for (i = 1; i < argc; i ++) {
		char *a;

		a = argv[i];
		if (strcasecmp(a, "-text") == 0) {
			text = 1;
		} else if (strcasecmp(a, "-outpub") == 0) {
			if (++ i == argc || outpub != NULL) {
				usage();
			}
			outpub = argv[i];
		} else if (strcasecmp(a, "-outpriv") == 0) {
			if (++ i == argc || outpriv != NULL) {
				usage();
			}
			outpriv = argv[i];
		} else {
			if (size != 0) {
				usage();
			}
			size = atoi(a);
		}
	}
	if (size < 1273 || size > 32768) {
		usage();
	}

	/* Generate the new private key. */
	CF(makwa_generate_key(size, NULL, &priv_len));
	priv = xmalloc(priv_len);
	CF(makwa_generate_key(size, priv, &priv_len));

	/* Write the private key file. */
	if (outpriv != NULL) {
		write_file(outpriv, priv, priv_len);
	}

	/* If a text printout and/or a public file is requested, then
	   obtain the modulus. */
	if (text || outpub != NULL) {
		CF(makwa_compute_modulus(priv, priv_len, NULL, &pub_len));
		pub = xmalloc(pub_len);
		CF(makwa_compute_modulus(priv, priv_len, pub, &pub_len));
		if (text) {
			size_t u;

			printf("modulus = 0x");
			for (u = 6; u < pub_len; u ++) {
				printf("%02X", pub[u]);
			}
			printf("\n");
		}
		if (outpub != NULL) {
			write_file(outpub, pub, pub_len);
		}
		xfree(pub);
	}

	xfree(priv);
	return 0;
}
