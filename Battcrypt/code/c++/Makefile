CC       = g++
CFLAGS64 = -c -Wall -m64 -O2
CFLAGS32 = -c -Wall -m32 -O2
LFLAGS64 = -m64
LFLAGS32 = -m32
 
all: battcrypt-64 battcrypt-32
	

# 64 bit
battcrypt-64: main64.o battcrypt64.o blowfish64.o sha51264.o
	$(CC) $(LFLAGS64) -o battcrypt-64 main64.o battcrypt64.o blowfish64.o sha51264.o

main64.o: main.cpp battcrypt.h common.h architecture.h
	$(CC) $(CFLAGS64) -o main64.o main.cpp

battcrypt64.o: battcrypt.cpp battcrypt.h blowfish.h sha512.h common.h architecture.h
	$(CC) $(CFLAGS64) -o battcrypt64.o battcrypt.cpp

blowfish64.o: blowfish.cpp blowfish.h common.h architecture.h
	$(CC) $(CFLAGS64) -o blowfish64.o blowfish.cpp

sha51264.o: sha512.cpp sha512.h common.h architecture.h
	$(CC) $(CFLAGS64) -o sha51264.o sha512.cpp

# 32 bit
battcrypt-32: main32.o battcrypt32.o blowfish32.o sha51232.o
	$(CC) $(LFLAGS32) -o battcrypt-32 main32.o battcrypt32.o blowfish32.o sha51232.o

main32.o: main.cpp battcrypt.h common.h architecture.h
	$(CC) $(CFLAGS32) -o main32.o main.cpp

battcrypt32.o: battcrypt.cpp battcrypt.h blowfish.h sha512.h common.h architecture.h
	$(CC) $(CFLAGS32) -o battcrypt32.o battcrypt.cpp

blowfish32.o: blowfish.cpp blowfish.h common.h architecture.h
	$(CC) $(CFLAGS32) -o blowfish32.o blowfish.cpp

sha51232.o: sha512.cpp sha512.h common.h architecture.h
	$(CC) $(CFLAGS32) -o sha51232.o sha512.cpp

clean:
	-rm *.o battcrypt-64 battcrypt-32
