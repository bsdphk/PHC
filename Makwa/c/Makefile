CC = gcc
CFLAGS = -W -Wall -O
LD = gcc
LDFLAGS = 
LIBS = -lcrypto

EXE = makeKAT selftest keygen deleggen
OBJ = makwa.o makeKAT.o selftest.o keygen.o deleggen.o phc.o

all: $(EXE)

makeKAT: makwa.o makeKAT.o
	$(LD) $(LDFLAGS) -o makeKAT makwa.o makeKAT.o $(LIBS)

selftest: makwa.o selftest.o phc.o
	$(LD) $(LDFLAGS) -o selftest makwa.o selftest.o phc.o $(LIBS)

keygen: makwa.o keygen.o
	$(LD) $(LDFLAGS) -o keygen makwa.o keygen.o $(LIBS)

deleggen: makwa.o deleggen.o
	$(LD) $(LDFLAGS) -o deleggen makwa.o deleggen.o $(LIBS)

makwa.o: makwa.c makwa.h
	$(CC) $(CFLAGS) -o makwa.o -c makwa.c

makeKAT.o: makeKAT.c makwa.h
	$(CC) $(CFLAGS) -o makeKAT.o -c makeKAT.c

selftest.o: selftest.c makwa.h
	$(CC) $(CFLAGS) -o selftest.o -c selftest.c

keygen.o: keygen.c makwa.h
	$(CC) $(CFLAGS) -o keygen.o -c keygen.c

deleggen.o: deleggen.c makwa.h
	$(CC) $(CFLAGS) -o deleggen.o -c deleggen.c

phc.o: phc.c makwa.h
	$(CC) $(CFLAGS) -o phc.o -c phc.c

clean:
	-rm -f $(OBJ) $(EXE)
