#!/bin/bash
# build script for Lanarea submission

# build libb2: provides BLAKE2
cd libb2/
./configure && make
cd ..

# build Lanarea
gcc -o test lanarea.c test.c ./libb2/src/.libs/libb2_la-blake2b.o -O2 -fprofile-generate $cflags
wait
# profile Lanarea
time ./test
wait
# rebuild and reprofile
gcc -o test lanarea.c test.c ./libb2/src/.libs/libb2_la-blake2b.o -O2 -fprofile-use -fprofile-generate $cflags
wait
# retest
time ./test
wait
# rebuild
gcc -o test lanarea.c test.c ./libb2/src/.libs/libb2_la-blake2b.o -O2 -fprofile-use $cflags
wait
# rerun
time ./test
wait
