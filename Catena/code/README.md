Catena
======
Catena is a memory-consuming password scrambler that excellently
thwarts massively parallel attacks on cheap memory-constrained
hardware, such as recent graphical processing units (GPUs).
Furthermore, Catena is resistance against cache-timing attacks, since
its memory-access pattern is password-independent.

Academic paper:
http://eprint.iacr.org/2013/525

Content
-------
* C reference implementation of Catena-blake2b 
* C reference implementation of Catena-sha512 (depends on libssl and libcrypto) 

Dependencies
------------
* gcc     (http://gcc.gnu.org/)
* openssl (http://www.openssl.org/)
* make    (http://www.gnu.org/software/make/)

