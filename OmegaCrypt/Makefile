CC=gcc
#CC=clang

# For GCC:
CFLAGS=-Wall -O2 -pedantic -pedantic-errors
#CFLAGS=-Wall -march=native -O2 -pedantic -pedantic-errors
#CFLAGS=-Wall -march=native -O2 -ansi -pedantic -pedantic-errors


# For LLVM clang:
#CFLAGS=-Wall -O2 -pedantic -pedantic-errors

# For debugging:
#CFLAGS=-Wall -O0 -ansi -pedantic -pedantic-errors -g

main: ocrypt_genKAT ocrypt_heatmap

ocrypt_genKAT: ocrypt_genKAT.o ocrypt.o chacha-wrapper.o nettle-chacha.o \
	       cubehash.o
	$(CC) $(CFLAGS) -o ocrypt_genKAT ocrypt_genKAT.o ocrypt.o cubehash.o \
			chacha-wrapper.o chacha-core-internal.o chacha-init.o \
			chacha-crypt.o memxor.o

ocrypt_genKAT.o: ocrypt_genKAT.c phs.h
	$(CC) $(CFLAGS) -c ocrypt_genKAT.c

ocrypt_heatmap: ocrypt_heatmap.o ocrypt.o chacha-wrapper.o nettle-chacha.o \
	       cubehash.o
	$(CC) $(CFLAGS) -o ocrypt_heatmap ocrypt_heatmap.o ocrypt.o \
			cubehash.o chacha-wrapper.o chacha-core-internal.o \
			chacha-init.o chacha-crypt.o memxor.o -lm

ocrypt_heatmap.o: ocrypt_heatmap.c phs.h
	$(CC) $(CFLAGS) -c ocrypt_heatmap.c

ocrypt.o: ocrypt.c ocrypt.h
	$(CC) $(CFLAGS) -c ocrypt.c

chacha-wrapper.o: chacha-wrapper.h chacha-wrapper.c
	$(CC) $(CFLAGS) -c chacha-wrapper.c

nettle-chacha.o: nettle-chacha/*.c nettle-chacha/*.h
	$(CC) $(CFLAGS) -c nettle-chacha/*.c

cubehash-test: cubehash-test.o cubehash.o
	$(CC) $(CFLAGS) -o cubehash-test cubehash-test.o cubehash.o

cubehash-test.o: cubehash-test.c
	$(CC) $(CFLAGS) -c cubehash-test.c

cubehash.o: cubehash.c cubehash.h
	$(CC) $(CFLAGS) -c cubehash.c

clean:
	rm -f ocrypt_genKAT
	rm -f ocrypt_heatmap
	rm -f cubehash-test
	rm -f *.o
	rm -f *~
	rm -f \#*
	rm -f nettle-chacha/*.o
	rm -f nettle-chacha/*~
	rm -f nettle-chacha/\#*
