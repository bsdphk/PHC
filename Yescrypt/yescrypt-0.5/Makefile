# Copyright 2013,2014 Alexander Peslyak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

CC = gcc
LD = $(CC)
RM = rm -f
OMPFLAGS = -fopenmp
OMPFLAGS_MAYBE = $(OMPFLAGS)
CFLAGS = -Wall -march=native -O2 -funroll-loops -fomit-frame-pointer $(OMPFLAGS_MAYBE)
#CFLAGS = -Wall -march=native -O2 -fomit-frame-pointer $(OMPFLAGS_MAYBE)
#CFLAGS = -Wall -O2 -fomit-frame-pointer $(OMPFLAGS_MAYBE)
LDFLAGS = -s $(OMPFLAGS_MAYBE)

PROJ = tests phc-test initrom userom
OBJS_CORE = yescrypt-best.o
OBJS_TESTS = $(OBJS_CORE) yescrypt-common.o sha256.o tests.o
OBJS_PHC = $(OBJS_CORE) yescrypt-common.o sha256.o phc-test.o
OBJS_INITROM = $(OBJS_CORE) yescrypt-common.o sha256.o initrom.o
OBJS_USEROM = $(OBJS_CORE) yescrypt-common.o sha256.o userom.o
OBJS_RM = yescrypt-*.o

all: $(PROJ)

check: tests phc-test
	@echo 'Running main tests'
	@time ./tests | tee TESTS-OUT
	@diff -U0 TESTS-OK TESTS-OUT && echo PASSED || echo FAILED
	@if [ -e PHC-TEST-OK ]; then \
		echo 'Running PHC tests'; \
		time ./phc-test > PHC-TEST-OUT; \
		cmp PHC-TEST-OK PHC-TEST-OUT && echo PASSED || echo FAILED; \
	fi

ref:
	$(MAKE) $(PROJ) OBJS_CORE=yescrypt-ref.o

check-ref:
	$(MAKE) check OBJS_CORE=yescrypt-ref.o

opt:
	$(MAKE) $(PROJ) OBJS_CORE=yescrypt-opt.o

check-opt:
	$(MAKE) check OBJS_CORE=yescrypt-opt.o

tests: $(OBJS_TESTS)
	$(LD) $(LDFLAGS) $(OBJS_TESTS) -o $@

phc-test.o: phc.c
	$(CC) -c $(CFLAGS) -DTEST phc.c -o $@

phc-test: $(OBJS_PHC)
	$(LD) $(LDFLAGS) $(OBJS_PHC) -o $@

initrom: $(OBJS_INITROM)
	$(LD) $(LDFLAGS) $(OBJS_INITROM) -o $@

userom: $(OBJS_USEROM)
	$(LD) $(LDFLAGS) $(OMPFLAGS) $(OBJS_USEROM) -o $@

userom.o: userom.c
	$(CC) -c $(CFLAGS) $(OMPFLAGS) $*.c

.c.o:
	$(CC) -c $(CFLAGS) $*.c

yescrypt-best.o: yescrypt-platform.c yescrypt-simd.c yescrypt-opt.c
yescrypt-simd.o: yescrypt-platform.c
yescrypt-opt.o: yescrypt-platform.c

clean:
	$(RM) $(PROJ)
	$(RM) $(OBJS_TESTS) $(OBJS_PHC) $(OBJS_INITROM) $(OBJS_USEROM)
	$(RM) $(OBJS_RM)
	$(RM) TESTS-OUT PHC-TEST-OUT
