CFLAGS = -Wall -O3

KECCAK_DEPS = KeccakF-1600-reference.o KeccakSponge.o displayIntermediateValues.o

test_catfish.run: main.c catfish.o pkhash_1024.o $(KECCAK_DEPS)
	gcc $(CFLAGS) main.c -c -o main.o
	gcc $(CFLAGS) -o $@ main.o catfish.o pkhash_1024.o $(KECCAK_DEPS)

check_test_vectors.run: check_test_vectors.c catfish.o pkhash_1024.o $(KECCAK_DEPS)
	gcc $(CFLAGS) check_test_vectors.c -c -o check_test_vectors.o
	gcc $(CFLAGS) -o $@ check_test_vectors.o catfish.o pkhash_1024.o $(KECCAK_DEPS)

catfish.o: catfish.c
	gcc $(CFLAGS) $^ -c -o $@

pkhash_1024.o: pkhash_1024.c
	gcc $(CFLAGS) $^ -c -o $@

KeccakSponge.o: KeccakSponge.c
	gcc $(CFLAGS) -c $^ -o $@

KeccakF-1600-reference.o: KeccakF-1600-reference.c
	gcc $(CFLAGS) -c -Wall $^ -o $@

displayIntermediateValues.o: displayIntermediateValues.c
	gcc -c -Wall $^ -o $@

.PHONY: clean
clean:
	rm -rf *.out *.o *.run
