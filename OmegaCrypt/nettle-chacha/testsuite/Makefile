#===================================================================
#
# Makefile
# --------
# Makefile for building ChaCha and the test code.
#
#
# (c) 2013 Joachim Strombergson
#
#===================================================================

SOURCES=test-chacha.c ../*.c 
INCLUDES=../*.h
INCDIR=/Users/js/Sandbox/proj/nettle/chacha/

all: test-chacha


test-chacha: $(SOURCES) $(INCLUDES)
	clang -Wall -O2 -o test-chacha $(SOURCES) -I$(INCDIR)


clean:
	rm test-chacha

#===================================================================
# EOF Makefile
#===================================================================

