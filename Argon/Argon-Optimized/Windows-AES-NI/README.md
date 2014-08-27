Argon Optimized for Windows with AES-NI support
=====

This implementation is optimized for x86/x64 architectures with AES-NI support. The AES instructions and 128-bit registers are used within intrinsics.

Parameters for benchmarking 256 MBytes with 4 threads: 
-taglength 32 -logmcost 18 -tcost 3 -pwdlen 64 -saltlen 16 -threads 4

Benchmarking for 2^d MBytes for d from 1 to 12 and for 1 to 16 threads:
-benchmark
