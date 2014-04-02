Yarn password hashing function
==============================

Author: Evgeny Kapun <abacabadabacaba@gmail.com>


Introduction
~~~~~~~~~~~~

I propose a password hashing function Yarn. It is a memory-hard function specifically tailored for modern x86 processors. Therefore, it may be useful on a wide range of desktop, laptop and server machines.

The function makes heavy use of `aesenc` x86 instruction and instruction-level parallelism, which is intended to make it difficult to compute on any other hardware. It has a number of parameters which can be tweaked to achieve the best possible resource utilization.


Specification
~~~~~~~~~~~~~

Notation: operation of various function below is described using pseudocode. In pseudocode, all values are either arbitrary-precision integers or byte sequences (or arrays of them). Operator <- represents assignment, ** represents exponentiation, and || represents string concatenation, other operators have the same meaning as in C.

The function takes the following parameters:

* Password (`in`) - a string up to 2**128 - 1 bytes in length.
* Salt (`salt`) (optional) - a string up to 16 bytes in length.
* Personalization string (`pers`) (optional) - a string up to 16 bytes in length.
* Output length (`outlen`) - a positive integer not exceeding 64.
* Time cost (`t_cost`) - a nonnegative integer.
* Memory cost (`m_cost`) - a nonnegative integer not exceeding 124. Memory requirement is 16 * 2**m_cost bytes.
* Internal paralellism level (`par`) - a positive integer.
* Number of rounds for the initial phase (`initrnd`) - a positive integer.
* Number of loops between memory accesses (`m_step`) - a positive integer.

Definitions:

Blake2b - a BLAKE2b hash function (http://blake2.net/). It consists of the following steps:

	function Blake2b(in, outlen, salt, pers):
		h <- Blake2b_GenerateInitialState(outlen, salt, pers)
		h <- Blake2b_ConsumeInput(h, in)
		return Truncate(h, outlen)

These steps will be used separately, as well as BLAKE2b compression function: Blake2b_Compress(h, m, t0, t1, f0, f1).

This function will be used to produce arbitrary number of pseudorandom bytes from a BLAKE2b state:

	function Blake2b_ExpandState(h, outlen):
		out <- <empty string>
		i <- 0
		while Length(out) < outlen:
			out <- out || Blake2b_Compress(h, <128 null bytes>, Low64Bits(i), High64Bits(i), 0, 0xffffffffffffffff)
			i <- i + 1
		return Truncate(out, outlen)

AESEnc - a round of AES encryption, equivalent to x86 `aesenc` instruction. Can be represented as:

	function AESEnc(data, key):
		return AESPermutation(data) ^ key

Here, AESPermutation is a combination of SubBytes, ShiftRows and MixColumns AES steps.

The following function is similar to AES encryption, but simplier. `keys` is an array of `initrnd` AES round keys:

	function AESPseudoEncrypt(data, keys):
		for i in 0 .. initrnd - 1:
			data <- AESEnc(data, keys[i])
		return data

Unlike real AES, there is no distinct initial and final rounds.

There are two main arrays used in Yarn function: `state` and `memory`. `state` consists of `par` 16-byte blocks, and `memory` consists of 2**m_cost 16-byte blocks. This function rotates `state` one block to the left:

	function RotateState(state):
		return state[1 .. par - 1] || state[0]

The function Integerify turns a 16-byte block into a valid index in `memory` array. It represents the entire block as a little-endian integer, then discards its 4 least significant bits and everything above its 4 + m_cost least significant bits. This can be summarized as follows (computations are assumed to be performed in arbitrary precision arithmetics):

	function Integerify(block):
		n <- AsLittleEndianInteger(block)
		return (n >> 4) & ((1 << m_cost) - 1)

The Yarn function consists of four phases. In the first phase, the password is hashed using BLAKE2b hash function, and its final state is used to derive pseudorandom initial values for `state`, `keys` and `index`. During the second phase, the `memory` array is filled with `par` interleaved OFB-mode keystreams computed using the AESPseudoEncrypt function. During the third phase, multiple AESEnc computations and random memory accesses are performed such that they can only be parallelized to a specific extent. During the final phase, the result of the third phase is compressed with the hash state produced in the first phase to obtain the final value of the hash.

	function Yarn(in, salt, pers, outlen, t_cost, m_cost, par, initrnd, m_step):
		// Phase 1 - initialization
		h <- Blake2b_GenerateInitialState(outlen, salt, pers)
		h <- Blake2b_ConsumeInput(h, in)
		expanded_h <- As16ByteBlocks(Blake2b_ExpandState(h, 16 * (par + initrnd + 1)))
		state <- expanded_h[0 .. par - 1]
		keys <- expanded_h[par .. par + initrnd - 1]
		index <- Integerify(expanded_h[par + initrnd])
		// Phase 2 - memory filling
		for i in 0 .. 2**m_cost:
			memory[i] <- state[0]
			state[0] <- AESPseudoEncrypt(state[0], keys)
			state <- RotateState(state)
		// Phase 3 - main phase
		for i in 0 .. t_cost - 1:
			block <- state[1 % par]
			if i % m_step == m_step - 1:
				block2 <- memory[index]
				memory[index] <- block
				block <- block xor block2
				index <- Integerify(block)
			state[0] <- AESEnc(state[0], block)
			state <- RotateState(state)
		// Phase 4 - finalization
		h <- Blake2b_ConsumeInput(h, AsBytes(state))
		return Truncate(h, outlen)


Security analysis
~~~~~~~~~~~~~~~~~

The security of the Yarn function rests on the security of BLAKE2b function, as well as on properties of AES encryption. Since the result of Yarn is essentially a BLAKE2b hash with some extra data cryptographycally compressed into it, Yarn has the same preimage and collision resistance properties as BLAKE2b. I also think that it has the same indifferentiability property as BLAKE2b, however, Yarn hashes of the same input computed with different parameter values might be related.

Straightforward computation of Yarn hash requires a number of iterative computation of AES permutation, and I believe that the properties of AES permutation don't permit to accelerate that computation significantly. Since the result of those AES operations is used as an input to BLAKE2b hash, it's not possible to skip computing those values as well.

The contents of `memory` is initialized using `par` interleaved AESPseudoEncrypt-OFB keystreams. While the security shouldn't depend on the initial memory contents being random, it doesn't do any harm. So I think that a good value for `initrnd`, which selects the number of AES rounds in AESPseudoEncrypt, is 10, which matches the number of rounds in AES-128.

Finally, random accesses to a memory region using unpredictable addresses bound the time necessary to compute Yarn hash by latency of available memory. Memory writes are performed together with reads to resist time-memory tradeoffs. As a side effect, efficient implementations are not resistant to cache-timing attacks. I don't know if it is possible to achieve both memory-hardness and side-channel resistance on common hardware.


Efficiency analysis
~~~~~~~~~~~~~~~~~~~

It is intended that the parameters are selected such that phase 3 takes the majority of the computation time. Phases 2 and 3 are designed such that it is possible to compute up to `par` AES permutations in parallel, but not more. According to an Intel manual [1], some Intel processors can evaluate approximately 8 AES instructions at a time, on the same core. However, I think that the optimal value for `par` is slightly less.

During the third phase, random memory accesses are also performed in parallel with AES operations. Modern x86 processors can execute instructions out of order, so many AES instructions can be executed in parallel with a single memory load. The `m_step` parameter conrols the relative timing between AES and memory operations. It should be tuned to utilize both AES units and memory at their maxumal speed.

This function deliberately doesn't take advantage of multithreading. I think that in order to utilize multithreading, a higher level primitive should be used, which will compute multiple instances of a function like this one in parallel and combine the results.

With the right choice of parameters, computing the Yarn function on GPU should be pretty slow, for the following reasons: I think that AES operations in phase 3 are sufficiently interwoven to make it infeasible to distribute the computation of one instance of phase 3 to multiple GPU cores. However, computing many AES operations on a GPU core is slow, and each instance also locks a chunk of GPU memory. Therefore, if `m_cost` is high enough, only a small fraction of GPU cores can be used for computation, which makes the computation on GPU inefficient.

To compute the function efficiently on FPGA and ASICs, it would be necessary to have both large amounts of memory and multiple AES units. However, a CPU has both already, so making a cost-effective FPGA or ASIC for the function would be tricky.

[1] http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf


Legal statements
~~~~~~~~~~~~~~~~

This scheme and the accompanying code doesn't contain any deliberately introduced deficiencies or weaknesses.

To the extent possible under law, I waive all copyright and related or neighboring rights to this document and the accompanying code.

I am not awere of any patents or patent applications covering this scheme.