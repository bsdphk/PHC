test_catfish.run: main.cc
	g++ -o $@ main.cc catfish.cc KeccakSponge.c KeccakF-1600-reference.c displayIntermediateValues.c -lssl -lcrypto

.PHONY: clean
clean:
	rm -rf *.run *.o *.out
