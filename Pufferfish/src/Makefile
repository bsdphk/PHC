CC        = cc
CFLAGS    = -g -Wall -pedantic -O3 -march=native
LIBS      = -lcrypto

all:  pfcrypt-ref pfcrypt-opt pfkdf-ref pfkdf-opt

pfcrypt-ref: pfcrypt-ref.o pufferfish-ref.o itoa64.o api-ref.o
	$(CC) -o pfcrypt-ref examples/pfcrypt-ref.o reference/pufferfish-ref.o common/itoa64.o common/api-ref.o $(LIBS)

pfcrypt-opt: pfcrypt-opt.o pufferfish-opt.o sha512.o hmac-sha512.o itoa64.o api-opt.o
	$(CC) -o pfcrypt-opt -DOPTIMIZED examples/pfcrypt-opt.o optimized/pufferfish-opt.o optimized/sha512.o optimized/hmac-sha512.o common/itoa64.o common/api-opt.o

pfkdf-ref: pfkdf-ref.o pufferfish-ref.o itoa64.o api-ref.o
	$(CC) -o pfkdf-ref examples/pfkdf-ref.o reference/pufferfish-ref.o common/itoa64.o common/api-ref.o $(LIBS)

pfkdf-opt: pfkdf-opt.o pufferfish-opt.o sha512.o hmac-sha512.o itoa64.o api-opt.o
	$(CC) -o pfkdf-opt -DOPTIMIZED examples/pfkdf-opt.o optimized/pufferfish-opt.o optimized/sha512.o optimized/hmac-sha512.o common/itoa64.o common/api-opt.o

pfcrypt-ref.o:
	$(CC) -c $(CFLAGS) -o examples/pfcrypt-ref.o examples/pfcrypt.c

pufferfish-ref.o:
	$(CC) -c $(CFLAGS) -o reference/pufferfish-ref.o reference/pufferfish.c

pfcrypt-opt.o:
	$(CC) -c $(CFLAGS) -DOPTIMIZED -o examples/pfcrypt-opt.o examples/pfcrypt.c

pufferfish-opt.o:
	$(CC) -c $(CFLAGS) -o optimized/pufferfish-opt.o optimized/pufferfish.c

sha512.o:
	$(CC) -c $(CFLAGS) -o optimized/sha512.o optimized/sha512.c

hmac-sha512.o:
	$(CC) -c $(CFLAGS) -o optimized/hmac-sha512.o optimized/hmac-sha512.c 

pfkdf-ref.o:
	$(CC) -c $(CFLAGS) -o examples/pfkdf-ref.o examples/pfkdf.c

pfkdf-opt.o:
	$(CC) -c $(CFLAGS) -DOPTIMIZED -o examples/pfkdf-opt.o examples/pfkdf.c

api-ref.o:
	$(CC) -c $(CFLAGS) -o common/api-ref.o common/api.c

api-opt.o:
	$(CC) -c $(CFLAGS) -DOPTIMIZED -o common/api-opt.o common/api.c

itoa64.o:
	$(CC) -c $(CFLAGS) -o common/itoa64.o common/itoa64.c

clean:
	rm -f pfcrypt-ref pfcrypt-opt pfkdf-ref pfkdf-opt examples/*.o common/*.o reference/*.o optimized/*.o
