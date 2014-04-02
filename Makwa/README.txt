This package contains the specification and reference implementations
for the Makwa password hashing function, as submitted to the
Password Hashing Competition. Included files are:

makwa-cover.pdf
    The cover letter for Makwa.

makwa-spec.pdf
    The specification document itself. It describes the function, how
    it works, and what it is meant to do.

c/
    The reference implementation, written in C. The OpenSSL library is
    used for some primitives (HMAC with SHA-256 and SHA-512, random
    number generation, and big integers).

java/
    An alternate implementation, written in Java.

kat.txt
    Known-Answer Tests for Makwa. Both C and Java implementations include
    code which generates that file.

==========================================================================

IMPLEMENTATION QUICK START GUIDE
--------------------------------

C CODE

The C reference implementation is a library, whose two main files are
makwa.h (the header file which declares the functions) and makwa.c (the
implementation of the Makwa functions). The makwa.h is heavily commented
and serves as documentation for the API.

Extra files are:

   phc.c
      Implementation of the PHS() function mandated for submissions to
      the Password Hashing Competition. It has been separated because it
      does not follow the naming scheme of the rest of the code, and
      thus could imply trouble when including it in a larger
      application; also, you should not use it because it works with a
      hardcoded modulus.

   selftest.c
      A main program source code which runs some tests on Makwa, including
      some speed measurements.

   makeKAT.c
      A main program source code which produces the Known-Answer Tests
      file.

   keygen.c
      Source for a command-line tool which generates new random private
      keys and modulus for Makwa.

   deleggen.c
      Source for a command-line tool which generates sets of delegation
      parameters (encoded values which are used to offload computations
      to an untrusted server).

   Makefile
      A standard Makefile which triggers compilation of the selftest,
      makeKAT, keygen and deleggen stand-alone programs.

To use Makwa in your own application, you need to import the makwa.c and
makwa.h files. The code uses OpenSSL for HMAC (with SHA-256 or SHA-512),
random number generation (for producing new salts), and for the
computationally expensive modular squarings which are at the core of
Makwa. Thus, Makwa performance is not noticeably impacted by the
optimization parameters (or lack thereof) used to compile makwa.c
itself; what matters is how OpenSSL was compiled.

On MacOS X 10.7+ platforms, you will get a lot of warnings, because
Apple deprecated OpenSSL. Moreover, the OS-provided OpenSSL is old
(0.9.8 derivative) and very suboptimal; a more recent version (1.0.1f)
provides a substantial 5x performance boost on 64-bit CPU.

On x86 platforms, if given the choice between the 32-bit ("i386") and
the 64-bit ("amd64") architectures, choose the latter: big integer
computations are widely more efficient in 64-bit mode than in 32-bit
mode (by a factor of almost 4).


JAVA CODE

The java/src/ directory contains a pure-Java implementation of Makwa. It
offers the same functionalities as the C code. The java/src/makwa/
directory contains the library itself; java/src/makwa/tools/ contains
some command-line tools called SelfTest, MakeKAT, KeyGen and DelegGen:
they provide the same services as their C counterparts.

The java/api/ directory contains the Javadoc-generated documentation for
the Makwa classes.

If you want to use this implementation of Makwa in your own application,
then you will have to import the classes from the "makwa" package; the
"makwa.tools" package can be left out (the tools use the library, not
the other way round).


API OVERVIEW

Both C and Java follow the same structure.

A context structure is first created and initialized with some
parameters (in C, a makwa_context structure; in Java, a makwa.Makwa
class instance). The two main parameters are the modulus and the
underlying hash function. A standard serialization format for a modulus
is supported. Alternatively, the modulus can be replaced with a private
key (internally, the two prime factors for the modulus); using a private
key unlocks some features (fast path, unescrow...) but requires more
operational care: you really do not want to see your private key stolen.
Since the serialization formats for modulus and private keys begin with
an explicit header, the initialization functions can accept both kinds
transparently.

Each Makwa hash operation must use some extra parameters:
-- salt: a sequence of bytes.
-- pre-hashing: a boolean flag.
-- post-hashing length: a target output length (in bytes), which can be
zero if no post-hashing is to be applied; without post-hashing, the
output length is equal to the modulus length.
-- work factor: a nonnegative integer.

The makwa_hash() function (Makwa.doHash() in Java) implements Makwa
itself. The extra parameters are provided explicitly.

A "simple API" is also provided. With the simple API:
-- The input is taken as a character string, not a sequence of bytes.
-- The output is encoded as an ASCII string, suitable for storage.
That string contains a copy of the extra parameters, a checksum on
the modulus (to reliably detect misconfiguration errors), and the
encoded output itself.
-- The extra parameters are not specified with each function call, but
at context initialization.

Such string-based outputs can be encoded and decoded at will with
dedicated functions (makwa_decode_string() in C, Makwa.decodeOutput() in
Java). On a general basis, you will want to use the simple API and
string-based encoding for password verification tasks: ASCII strings are
easy to store in databases, and aggregation of parameters into a single
value simplifies handling. On the other hand, for cryptographic purposes
(deriving the password into a key for symmetric algorithms), you will
want to use the low-level Makwa function itself.

Delegation is implemented by creating "requests": a hash operation is
used to populate a specific context structure (makwa_delegation_context
in C, Makwa.DelegationContext in Java). From that context, a "request"
(serialized as a sequence of bytes) can be obtained, and should be sent
to the delegation server. The "answer" can then be used with the context
to terminate the computation. An implementation of the server-side code
is provided (makwa_delegation_answer(), Makwa.processDelegationRequest()).

Delegation requires some precomputed "delegation parameters" which are
represented as specific stuctures (makwa_delegation_parameters,
MakwaDelegation). Such a set of parameters is generated for a single
work factor. A set can be serialized, there again with a standard format.

Extra functions are provided to change the work factor of an already
produced hash output (work factor decrease requires the private key),
and to unescrow passwords. A function implementing the inner KDF is
also provided (makwa_kdf(), Makwa.doKDF()).

==========================================================================

KNOWN-ANSWER TEST FORMAT
------------------------

The kat.txt file is generated with 'makeKAT' (makwa.tools.MakeKAT in
Java). Its format is a sequence of text lines. Lines occur in groups,
separated by blank lines. Each group begins with a line which is
either "KDF/SHA-256" (or "KDF/SHA-512") for a KDF test vector, or
"2048-bit modulus, SHA-256" (or idem, with SHA-512) for a Makwa test
vector.

For a KDF vector, the input and output are provided in hexadecimal, as
two lines.

For a Makwa vector, the input and salt are provided in hexadecimal; the
pre-hashing flag as a boolean ("true" or "false"); the post-hashing as
either "false" (no post-hashing) or a decimal integer. Output is then
provided as binary (a "bin" line, with hexadecimal output) and as an
encoded string (a "str" line). Each output line contains the work factor
(i.e. a "bin384" line contains the binary output, encoded in
hecadecimal, for Makwa with a work factor of 384).

All the outputs are also concatenated together, and hashed (with
SHA-256). The final hash value thus characterizes all KAT vectors.
If the final digest is correct, then, with overwhelming probability,
all vectors are correct. The binary outputs are hashed "as is"; the
string outputs are encoded in UTF-8 (actually ASCII, since these
strings are pure ASCII).

The KAT vectors have been designed to exercise classic failure
conditions (bytes in the 128..255 range, null bytes...). Refer to
makeKAT.c or makwa/tools/MakeKAT.java for details.

==========================================================================

LICENSE AND PATENTS
-------------------

I am not aware of any patent covering all or part of Makwa. I have not
filed any such patent myself, and I don't intend to.

Both the algorithm and the reference implementations are free to use by
anybody for any purpose on a royalty-free basis, subject to no condition
except as mandated by Law (which is not in my formal power to bend), and
under the understanding that I am not to be blamed for anything.
Function and code are provided 'as is', and any subsequent damage is
your fault, not mine. By using Makwa and its implementations, you
acknowledge that I don't guarantee anything; you are on your own.

In jurisdictions where such an assertion makes sense, I hereby put the
Makwa reference implementations (both C and Java) under Public Domain.

==========================================================================

A FINAL WARNING
---------------

As I write these lines, Makwa is still the child of a single brain
(mine). It would be overly assertive, even brash, for me to claim that
Makwa is ready for production and obviously secure. Though some
arguments about Makwa security are presented in the specification
document, actual security cannot be proven in an absolute way; the best
we can do to assess the robustness of any cryptographic algorithm is, in
practice, to let it cook under the fiery gaze of many cryptographers for
a few years. The point of the password hashing competition is indeed
to organize such a process.

Therefore, don't use Makwa yet. If it survives the academic onslaught,
then it may be declared "fit for service" in a few years. In the mean
time, it would be risky to use it as a basis for your security.


	--Thomas Pornin, <pornin@bolet.org>, February 22, 2014.
