/*-
 * Copyright 2013,2014 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>

#define YESCRYPT_FLAGS (YESCRYPT_RW | YESCRYPT_PARALLEL_SMIX | YESCRYPT_PWXFORM)
//#define YESCRYPT_FLAGS (YESCRYPT_RW | YESCRYPT_PWXFORM)
//#define YESCRYPT_FLAGS (YESCRYPT_RW | YESCRYPT_PARALLEL_SMIX)
#if 1
#define YESCRYPT_P 41
#define YESCRYPT_PROM 8
#else
#define YESCRYPT_P 1
#define YESCRYPT_PROM 1
#endif

#undef TEST_PBKDF2_SHA256
#define TEST_SCRYPT
#define TEST_YESCRYPT_ENCODING
#define TEST_ROM
#define TEST_ROM_PREALLOC

#ifdef TEST_ROM_PREALLOC
#include <stdlib.h> /* for malloc() */
#endif

#ifdef TEST_PBKDF2_SHA256
#include <assert.h>

#include "sha256.h"

static void
print_PBKDF2_SHA256_raw(const char * passwd, size_t passwdlen,
    const char * salt, size_t saltlen, uint64_t c, size_t dkLen)
{
	uint8_t dk[64];
	int i;

	assert(dkLen <= sizeof(dk));

	/* XXX This prints the strings truncated at first NUL */
	printf("PBKDF2_SHA256(\"%s\", \"%s\", %llu, %lu) =",
	    passwd, salt, (unsigned long long)c, dkLen);

	PBKDF2_SHA256((const uint8_t *) passwd, passwdlen,
	    (const uint8_t *) salt, saltlen, c, dk, dkLen);

	for (i = 0; i < dkLen; i++)
		printf(" %02x", dk[i]);
	puts("");
}

static void
print_PBKDF2_SHA256(const char * passwd, const char * salt, uint64_t c,
    size_t dkLen)
{
	print_PBKDF2_SHA256_raw(passwd, strlen(passwd), salt, strlen(salt), c,
	    dkLen);
}
#endif

#if defined(TEST_SCRYPT) || defined(TEST_YESCRYPT_ENCODING)
#include "yescrypt.h"
#endif

#ifdef TEST_SCRYPT
static void
print_scrypt(const char * passwd, const char * salt,
    uint64_t N, uint32_t r, uint32_t p)
{
	uint8_t dk[64];
	int i;

	printf("scrypt(\"%s\", \"%s\", %llu, %u, %u) =",
	    passwd, salt, (unsigned long long)N, r, p);

	if (crypto_scrypt((const uint8_t *) passwd, strlen(passwd),
	    (const uint8_t *) salt, strlen(salt), N, r, p, dk, sizeof(dk))) {
		puts(" FAILED");
		return;
	}

	for (i = 0; i < sizeof(dk); i++)
		printf(" %02x", dk[i]);
	puts("");
}
#endif

int
main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);

#ifdef TEST_PBKDF2_SHA256
	print_PBKDF2_SHA256("password", "salt", 1, 20);
	print_PBKDF2_SHA256("password", "salt", 2, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 20);
	print_PBKDF2_SHA256("password", "salt", 16777216, 20);
	print_PBKDF2_SHA256("passwordPASSWORDpassword",
	    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
	print_PBKDF2_SHA256_raw("pass\0word", 9, "sa\0lt", 5, 4096, 16);
#if 0
	print_PBKDF2_SHA256("password", "salt", 1, 32);
	print_PBKDF2_SHA256("password", "salt", 2, 32);
	print_PBKDF2_SHA256("password", "salt", 4096, 32);
	print_PBKDF2_SHA256("password", "salt", 16777216, 32);
	print_PBKDF2_SHA256("passwordPASSWORDpassword",
	    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40);
	print_PBKDF2_SHA256("password", "salt", 4096, 16);
	print_PBKDF2_SHA256("password", "salt", 1, 20);
	print_PBKDF2_SHA256("password", "salt", 2, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 20);
	print_PBKDF2_SHA256("password", "salt", 16777216, 20);
	print_PBKDF2_SHA256("password", "salt", 4096, 25);
	print_PBKDF2_SHA256("password", "salt", 4096, 16);
#endif
#endif

#ifdef TEST_SCRYPT
	print_scrypt("", "", 16, 1, 1);
	print_scrypt("password", "NaCl", 1024, 8, 16);
	print_scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1);
	print_scrypt("pleaseletmein", "SodiumChloride", 1048576, 8, 1);
#endif

#ifdef TEST_YESCRYPT_ENCODING
	{
		uint8_t * setting = yescrypt_gensalt(14, 8,
		    YESCRYPT_P, YESCRYPT_FLAGS,
		    (const uint8_t *)"binary data", 12);
		printf("'%s'\n", (char *)setting);
		if (setting) {
			uint8_t * hash = yescrypt(
			    (const uint8_t *)"pleaseletmein", setting);
			printf("'%s'\n", (char *)hash);
			if (hash)
				printf("'%s'\n", (char *)yescrypt(
				    (const uint8_t *)"pleaseletmein", hash));
		}
		printf("'%s'\n", (char *)yescrypt(
		    (const uint8_t *)"pleaseletmein",
		    (const uint8_t *)"$7$C6..../....SodiumChloride"));

#ifdef TEST_ROM
		uint64_t rom_bytes = 3 * (1024ULL*1024*1024);
		uint64_t ram_bytes = 2 * (1024ULL*1024);
		uint32_t r;
		uint64_t NROM_log2, N_log2;
		yescrypt_shared_t shared;
		yescrypt_local_t local;

		NROM_log2 = 0;
		while (((rom_bytes >> NROM_log2) & 0xff) == 0)
			NROM_log2++;
		r = rom_bytes >> (7 + NROM_log2);
		while (r < 5 && NROM_log2 > 0) {
			r <<= 1;
			NROM_log2--;
		}
		rom_bytes = (uint64_t)r << (7 + NROM_log2);

		N_log2 = 0;
		while ((r << (7 + N_log2)) < ram_bytes)
			N_log2++;
		ram_bytes = (uint64_t)r << (7 + N_log2);

		printf("r=%u N=2^%u NROM=2^%u\n", r,
		    (unsigned int)N_log2, (unsigned int)NROM_log2);

		printf("Will use %.2f KiB ROM\n", rom_bytes / 1024.0);
		printf("         %.2f KiB RAM\n", ram_bytes / 1024.0);

		printf("Initializing ROM ...");
		fflush(stdout);
		if (yescrypt_init_shared(&shared,
		    (uint8_t *)"local param", 12,
		    (uint64_t)1 << NROM_log2, r,
		    YESCRYPT_PROM, YESCRYPT_SHARED_DEFAULTS, 1,
		    NULL, 0)) {
			puts(" FAILED");
			return 1;
		}
		puts(" DONE");

		if (yescrypt_init_local(&local)) {
			puts("FAILED");
			return 1;
		}

		setting = yescrypt_gensalt(
		    N_log2, r, YESCRYPT_P, YESCRYPT_FLAGS,
		    (const uint8_t *)"binary data", 12);
		printf("'%s'\n", (char *)setting);

		uint8_t hash[128];

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmein", 13, setting,
		    hash, sizeof(hash)));

#ifdef TEST_ROM_PREALLOC
		yescrypt_free_shared(&shared);

		shared.shared1.aligned_size =
		    ((uint64_t)1 << NROM_log2) * 128 * r * 1;
		shared.shared1.aligned = malloc(shared.shared1.aligned_size);

/* These should be unused by yescrypt_init_shared() */
		shared.shared1.base_size = 0;
		shared.shared1.base = NULL;

		void * where = shared.shared1.aligned;

		printf("Initializing ROM in preallocated memory ...");
		fflush(stdout);
		if (yescrypt_init_shared(&shared,
		    (uint8_t *)"local param", 12,
		    (uint64_t)1 << NROM_log2, r,
		    YESCRYPT_PROM, YESCRYPT_SHARED_PREALLOCATED, 1,
		    NULL, 0)) {
			puts(" FAILED");
			return 1;
		}
		puts(" DONE");

		if (where != shared.shared1.aligned)
			puts("YESCRYPT_SHARED_PREALLOCATED failed");
#endif

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmein", 13, setting,
		    hash, sizeof(hash)));

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmeIn", 13, setting,
		    hash, sizeof(hash)));

		setting = yescrypt_gensalt(
		    N_log2, r, YESCRYPT_P, YESCRYPT_FLAGS,
		    (const uint8_t *)"binary Data", 12);

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmein", 13, setting,
		    hash, sizeof(hash)));

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmeIn", 13, setting,
		    hash, sizeof(hash)));
#endif
	}
#endif

	return 0;
}
