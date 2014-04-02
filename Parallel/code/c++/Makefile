CC       = g++
CFLAGS64 = -c -Wall -m64 -O2
CFLAGS32 = -c -Wall -m32 -O2
LFLAGS64 = -m64
LFLAGS32 = -m32
 
all: parallel-64 parallel-32
	

# 64 bit
parallel-64: main64.o parallel64.o sha51264.o
	$(CC) $(LFLAGS64) -o parallel-64 main64.o parallel64.o sha51264.o

main64.o: main.cpp parallel.h common.h architecture.h
	$(CC) $(CFLAGS64) -o main64.o main.cpp

parallel64.o: parallel.cpp parallel.h sha512.h common.h architecture.h
	$(CC) $(CFLAGS64) -o parallel64.o parallel.cpp

sha51264.o: sha512.cpp sha512.h common.h architecture.h
	$(CC) $(CFLAGS64) -o sha51264.o sha512.cpp

# 32 bit
parallel-32: main32.o parallel32.o sha51232.o
	$(CC) $(LFLAGS32) -o parallel-32 main32.o parallel32.o sha51232.o

main32.o: main.cpp parallel.h common.h architecture.h
	$(CC) $(CFLAGS32) -o main32.o main.cpp

parallel32.o: parallel.cpp parallel.h sha512.h common.h architecture.h
	$(CC) $(CFLAGS32) -o parallel32.o parallel.cpp

sha51232.o: sha512.cpp sha512.h common.h architecture.h
	$(CC) $(CFLAGS32) -o sha51232.o sha512.cpp

clean:
	-rm *.o parallel-64 parallel-32
