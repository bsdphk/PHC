CC=gcc
CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pedantic -g -march=native -funroll-loops
LIBS=-lcrypto

skinnycat: skinnycat.c skinnycat.h
	$(CC) $(CFLAGS) -DSKINNYCAT_TEST ../blake2-ref/blake2s-ref.c skinnycat.c -o skinnycat $(LIBS)

clean:
	rm skinnycat
