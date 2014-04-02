CC=gcc
HDIR=./blake2
CFLAGS=-fomit-frame-pointer -O3 -std=c99 -fgnu89-inline -s -m64 -msse4.2 -W -Wall -L$(HDIR) -I$(HDIR)

HASH=$(HDIR)/blake2b.c

all: blake2b sha512

blake2b: catena-blake2b-test catena-blake2b-test_vectors 
sha512: catena-sha512-test catena-sha512-test_vectors

catena-blake2b-test:
	$(CC) $(CFLAGS) -o $@ test-catena.c catena.c catena-blake2b.c $(HASH)


catena-blake2b-test_vectors:
	$(CC) $(CFLAGS) -o $@ catena_test_vectors.c catena.c catena-blake2b.c $(HASH)


catena-sha512-test:
	$(CC) $(CFLAGS) -o $@ test-catena.c catena.c catena-sha512.c -lssl -lcrypto


catena-sha512-test_vectors:
	$(CC) $(CFLAGS) -o $@ catena_test_vectors.c catena.c catena-sha512.c -lssl -lcrypto

catena:
	$(CC) $(CFLAGS) -c $@.c $(HASH)

clean:
	rm -f  *~ *.o catena-blake2b-test catena-blake2b-test_vectors catena-sha512-test catena-sha512-test_vectors catena-blake2b-opt-test catena2-sha512-test