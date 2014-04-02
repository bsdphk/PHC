#
# This file is part of Lyra2, a password hashing scheme
# Copyright (c) 2013-2014 by Lyra2 Project - - <http://www.lyra-kdf.net/>
#


CC?=gcc
NVCC=nvcc
CFLAGS=-std=c99 -Wall -pedantic -O3

BIN=../bin/Lyra2
BINCUDA=../bin/Lyra2CUDA
nCols=64

SSEDIR=sse/

# CUDA Flags
PTX = 10  # Must suits the GPU board used.
SM = 20   # Must suits the GPU board used.
CUDADIR=cuda/

default:
	
	@echo " "
	@echo "To build Lyra2, type:"
	@echo "      make OPTION [nCols=(number of columns, default 64)]"
	@echo " "
	@echo "where OPTION can be one of the following:"
	@echo "generic-x86-64                      For x86-64 Unix-like system, with gcc (i.e., Linux, FreeBSD, Mac OS, etc.)"
	@echo "linux-x86-64-sse2                   Linux x86-64, with SSE2 (beta version, needs improvement)"
	@echo "linux-x86-64-cuda                   Linux x86-64 (native), with CUDA (experimental)"
	@echo "linux-x86-64-cuda-tested-arch       Linux x86-64 (native), with CUDA (on architecture where the tests were performed)"
	@echo "windows-x86-64                      Windows x86-64, Cygwin"
	@echo "win-cygwin-x86-64-sse2              Windows x86-64, Cygwin, with SSE2 (beta version, needs improvement)"
	@echo " "
	@echo "Note:"
	@echo "Lyra2 was tested with nCols=16, nCols=32, nCols=64, nCols=96, and nCols=128 "
	@echo " "


generic-x86-64:	    Lyra2.c Sponge.c Main.c Lyra2.h Sponge.h
	$(CC) $(CFLAGS) Sponge.c Lyra2.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"

linux-x86-64-sse2:	$(SSEDIR)Lyra2.c $(SSEDIR)Sponge.c Main.c $(SSEDIR)Lyra2.h $(SSEDIR)Sponge.h
	$(CC) $(CFLAGS) $(SSEDIR)Sponge.c $(SSEDIR)Lyra2.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"
	
linux-x86-64-cuda:  $(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu $(CUDADIR)Lyra2.h $(CUDADIR)Sponge.h
	$(NVCC) $(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu -O3 -o $(BINCUDA) -lcudart -DN_COLS=$(nCols)
	@echo "Build completed, binaries in $(BINCUDA)"

linux-x86-64-cuda-tested-arch:	$(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu $(CUDADIR)Lyra2.h $(CUDADIR)Sponge.h
	$(NVCC) $(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu -O3  -arch=compute_$(PTX)  -code=sm_$(SM) -o $(BINCUDA) -lcudart -DN_COLS=$(nCols)
	@echo "Build completed, binaries in $(BINCUDA)"
	
windows-x86-64:	    Lyra2.c Sponge.c Main.c Lyra2.h Sponge.h
	$(CC) $(CFLAGS) Sponge.c Lyra2.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"

win-cygwin-x86-64-sse2:	$(SSEDIR)Lyra2.c $(SSEDIR)Sponge.c Main.c $(SSEDIR)Lyra2.h $(SSEDIR)Sponge.h
	$(CC) $(CFLAGS) $(SSEDIR)Sponge.c $(SSEDIR)Lyra2.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"
	
clean:
	rm -rf *.o $(BIN) $(BINCUDA)


