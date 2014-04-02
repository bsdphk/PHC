FLAGS_REF = -std=c89 -g -O -Wall -Wextra -DEARWORM_BUILD_REF
FLAGS_OPT = -mmmx -msse -msse2 -msse3 -msse4 -maes -O3 -funroll-loops -Wall -Wextra -DEARWORM_BUILD_OPT -DNDEBUG

HEADERS = aes.h core.h phc.h sha256.h util.h util-ref.h util-opt.h

OBJS_REF = aes-ref.o core-ref.o phc-ref.o sha256-ref.o test-ref.o
OBJS_OPT = aes-opt.o core-opt.o phc-opt.o sha256-opt.o test-opt.o

TARGETS_REF = test-ref
TARGETS_OPT = test-opt

LIBS = -lpthread

all: ref opt
ref: $(TARGETS_REF)
opt: $(TARGETS_OPT)

clean:
	$(RM) $(OBJS_REF) $(OBJS_OPT) $(TARGETS_REF) $(TARGETS_OPT)

aes-ref.o: aes.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_REF) $(CPPFLAGS) $(CFLAGS) $<

aes-opt.o: aes.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_OPT) $(CPPFLAGS) $(CFLAGS) $<

core-ref.o: core-ref.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_REF) $(CPPFLAGS) $(CFLAGS) $<

core-opt.o: core-opt.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_OPT) $(CPPFLAGS) $(CFLAGS) $<

phc-ref.o: phc.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_REF) $(CPPFLAGS) $(CFLAGS) $<

phc-opt.o: phc.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_OPT) $(CPPFLAGS) $(CFLAGS) $<

sha256-ref.o: sha256.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_REF) $(CPPFLAGS) $(CFLAGS) $<

sha256-opt.o: sha256.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_OPT) $(CPPFLAGS) $(CFLAGS) $<

test-ref.o: test.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_REF) -I. $(CPPFLAGS) $(CFLAGS) $<

test-opt.o: test.c $(HEADERS)
	$(CC) -o $@ -c $(FLAGS_OPT) -I. $(CPPFLAGS) $(CFLAGS) $<

test-opt: $(OBJS_OPT)
	$(CC) -o $@ $^ $(LIBS)

test-ref: $(OBJS_REF)
	$(CC) -o $@ $^ $(LIBS)

.PHONY: all ref opt clean
