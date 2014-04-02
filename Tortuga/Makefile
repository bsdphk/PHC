CFLAGS=-O3

TEST_OBJECTS=test.o phs.a

LIBS=-lm

all: phs.a

phs.a: turtle.o tortuga.o phs.o
	ar rcs phs.a $?

test: $(TEST_OBJECTS)
	$(CC) $? -o $@ $(LIBS)

clean:
	rm -f *.o *.a test
