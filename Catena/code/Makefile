
all: blake2b sha512

blake2b:
	cd src; make $@; cd 
	cp src/catena-$@-test .
	cp src/catena-$@-test_vectors .


sha512:
	cd src; make $@; cd ..
	cp src/catena-$@-test .
	cp src/catena-$@-test_vectors .

clean:
	cd src;	make clean; cd ..
	rm -f *~ catena-blake2b-test catena-sha512-test 
	rm -f catena-blake2b-test_vectors catena-sha512-test_vectors