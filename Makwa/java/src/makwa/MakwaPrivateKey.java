/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

package makwa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * <p>A {@code MakwaPrivateKey} instance encapsulates a Makwa private
 * key, i.e. the two prime factors whose product is the Makwa
 * modulus.</p>
 * 
 * <p>A new private key can be generated with {@link #generate}. The
 * target modulus size (in bits) is provided; it must be at least
 * 1273 bits (the normal modulus size is 2048 bits).</p>
 *
 * <p>Private and public keys can be encoded into array of bytes; the
 * {@link #exportPrivate} and {@link #exportPublic} methods implement
 * this serialization. Decoding can be done in several ways:</p>
 * <ul>
 * <li>A new {@code MakwaPrivateKey} instance can be created over an
 * encoded private key used as parameter for the constructor.</li>
 * <li>A public key is actually the modulus; encoding and decoding
 * can be performed with the static {@link #encodePublic} and
 * {@link #decodePublic} methods.</li>
 * <li>The {@link Makwa} class can be instantiated with an encoded
 * public or private key as first parameter.</li>
 * </ul>
 *
 * <p>The encoded format for a modulus consists in the concatenation,
 * in that order, of the following:</p>
 * <ul>
 * <li>a four-byte header: 55 41 4D 30</li>
 * <li>the modulus as a multi-precision integer (MPI):
 *    <ul>
 *    <li>an integer value "{@code len}" encoded in unsigned big-endian
 *    convention over exactly two bytes;</li>
 *    <li>exactly {@code len} bytes which encode the modulus in unsigned
 *    big-endian convention.</li>
 *    </ul>
 * When a MPI is encoded, the minimal length encoding should be used
 * (no leading byte of value 0x00).</li>
 * </ul>
 *
 * <p>The encoded format for a private consists in the concatenation,
 * in that order, of the following:</p>
 * <ul>
 * <li>a four-byte header: 55 41 4D 31</li>
 * <li>the first prime factor, as a MPI;</li>
 * <li>the second prime factor, as a MPI.</li>
 * </ul>
 *
 * <p>When encoding a private key, the greatest of the two prime factors
 * is supposed to come first.</p>
 *
 * <p>Instances of {@code MakwaPrivateKey} are immutable and
 * thread-safe.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class MakwaPrivateKey {

	private BigInteger p;
	private BigInteger q;
	private BigInteger modulus;
	private BigInteger invQ;

	/**
	 * Create a new instance by decoding a private key. This method
	 * makes some sanity checks but does not verify that the two
	 * prime integers are indeed prime.
	 *
	 * @param encoded   the encoded private key
	 * @throws MakwaException  on error
	 */
	public MakwaPrivateKey(byte[] encoded)
	{
		try {
			InputStream in = new ByteArrayInputStream(encoded);
			int magic = MakwaIO.read32(in);
			if (magic != MakwaIO.MAGIC_PRIVKEY) {
				throw new MakwaException(
					"not an encoded Makwa private key");
			}
			BigInteger p = MakwaIO.readMPI(in);
			BigInteger q = MakwaIO.readMPI(in);
			if (in.read() >= 0) {
				throw new MakwaException("invalid Makwa"
					+ " private key (trailing garbage)");
			}
			init(p, q);
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid Makwa private key (truncated)");
		}
	}

	/**
	 * Create a new instance with two specific primes. This method
	 * makes some sanity checks but does not verify that the two
	 * prime integers are indeed prime.
	 *
	 * @param p   the first prime factor
	 * @param q   the second prime factor
	 */
	public MakwaPrivateKey(BigInteger p, BigInteger q)
	{
		init(p, q);
	}

	private void init(BigInteger p, BigInteger q)
	{
		if (p.signum() <= 0 || q.signum() <= 0
			|| (p.intValue() & 3) != 3
			|| (q.intValue() & 3) != 3
			|| p.equals(q))
		{
			throw new MakwaException("invalid Makwa private key");
		}
		if (p.compareTo(q) < 0) {
			// We normally want the first prime to be the
			// largest of the two. This can help some
			// implementations of the CRT.
			BigInteger t = p;
			p = q;
			q = t;
		}
		this.p = p;
		this.q = q;
		modulus = p.multiply(q);
		if (modulus.bitLength() < 1273) {
			throw new MakwaException("invalid Makwa private key");
		}
		try {
			invQ = q.modInverse(p);
		} catch (ArithmeticException ae) {
			// This cannot happen if p and q are distinct
			// and both prime, as they should.
			throw new MakwaException(ae);
		}
	}

	/**
	 * Get the modulus (public key).
	 *
	 * @return  the Makwa modulus
	 */
	public BigInteger getModulus()
	{
		return modulus;
	}

	/**
	 * Generate a new private key. A secure PRNG is used to produce
	 * the new private key. The target modulus size (in bits) is
	 * provided as parameter; it must be no smaller than 1273 bits,
	 * and no greater than 32768 bits. The normal and recommended
	 * modulus size is 2048 bits.
	 *
	 * @param size   the target modulus size
	 * @return  the new private key
	 * @throws MakwaException  on error
	 */
	public static MakwaPrivateKey generate(int size)
	{
		if (size < 1273 || size > 32768) {
			throw new MakwaException(
				"invalid modulus size: " + size);
		}
		int sizeP = (size + 1) >> 1;
		int sizeQ = size - sizeP;
		BigInteger p = makeRandPrime(sizeP);
		BigInteger q = makeRandPrime(sizeQ);
		MakwaPrivateKey k = new MakwaPrivateKey(p, q);
		if (k.getModulus().bitLength() != size) {
			throw new MakwaException("key generation error");
		}
		return k;
	}

	/**
	 * Encode the private key into bytes.
	 *
	 * @return  the encoded private key
	 */
	public byte[] exportPrivate()
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			MakwaIO.write32(out, MakwaIO.MAGIC_PRIVKEY);
			MakwaIO.writeMPI(out, p);
			MakwaIO.writeMPI(out, q);
			return out.toByteArray();
		} catch (IOException ioe) {
			// Cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Encode the public key (modulus) into bytes.
	 *
	 * @return  the encoded modulus
	 */
	public byte[] exportPublic()
	{
		return encodePublic(modulus);
	}

	/**
	 * Encode a modulus into bytes.
	 *
	 * @param modulus   the modulus
	 * @return  the encoded modulus
	 */
	public static byte[] encodePublic(BigInteger modulus)
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			MakwaIO.write32(out, MakwaIO.MAGIC_PUBKEY);
			MakwaIO.writeMPI(out, modulus);
			return out.toByteArray();
		} catch (IOException ioe) {
			// Cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Decode a modulus from its encoded representation.
	 *
	 * @param encoded   the encoded modulus
	 * @return  the modulus
	 * @throws MakwaException  on error
	 */
	public static BigInteger decodePublic(byte[] encoded)
	{
		try {
			InputStream in = new ByteArrayInputStream(encoded);
			int magic = MakwaIO.read32(in);
			if (magic != MakwaIO.MAGIC_PUBKEY) {
				throw new MakwaException(
					"not an encoded Makwa modulus");
			}
			BigInteger mod = MakwaIO.readMPI(in);
			if (in.read() >= 0) {
				throw new MakwaException("invalid Makwa"
					+ " modulus (trailing garbage)");
			}
			return mod;
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid Makwa private key (truncated)");
		}
	}

	BigInteger getP()
	{
		return p;
	}

	BigInteger getQ()
	{
		return q;
	}

	BigInteger getInvQ()
	{
		return invQ;
	}

	private static SecureRandom RNG;

	static synchronized void prng(byte[] buf)
	{
		if (RNG == null) {
			RNG = new SecureRandom();
		}
		RNG.nextBytes(buf);
	}

	static BigInteger makeRandInt(BigInteger m)
	{
		if (m.signum() <= 0) {
			throw new MakwaException("invalid modulus (negative)");
		}
		if (m.equals(BigInteger.ONE)) {
			return BigInteger.ZERO;
		}
		int blen = m.bitLength();
		int len = (blen + 7) >>> 3;
		int mask = 0xFF >>> (8 * len - blen);
		byte[] buf = new byte[len];
		for (;;) {
			prng(buf);
			buf[0] &= (byte)mask;
			BigInteger z = new BigInteger(1, buf);
			if (z.compareTo(m) < 0) {
				return z;
			}
		}
	}

	static BigInteger makeRandNonZero(BigInteger m)
	{
		if (m.compareTo(BigInteger.ONE) <= 0) {
			throw new MakwaException(
				"invalid modulus (less than 2)");
		}
		for (;;) {
			BigInteger z = makeRandInt(m);
			if (z.signum() != 0) {
				return z;
			}
		}
	}

	/**
	 * Create a random prime of the provided length (in bits). The
	 * prime size must be at least 8 bits. Moreover, the two top
	 * bits of the resulting prime are forced to 1; this allows to
	 * target a specific modulus size (the product of two 512-bit
	 * primes with the two top bits set is necessarily a 1024-bit
	 * integer, not 1023). Moreover, the prime is guaranteed to be
	 * equal to 3 modulo 4.
	 *
	 * @param size   the target prime size
	 * @return  the new random prime
	 */
	private static BigInteger makeRandPrime(int size)
	{
		int len = (size + 8) >>> 3;
		byte[] buf = new byte[len];
		int mz16 = 0xFFFF >>> (8 * len - size);
		int mo16 = 0xC000 >>> (8 * len - size);
		for (;;) {
			prng(buf);
			buf[0] &= (byte)(mz16 >>> 8);
			buf[1] &= (byte)mz16;
			buf[0] |= (byte)(mo16 >>> 8);
			buf[1] |= (byte)mo16;
			buf[len - 1] |= (byte)0x03;
			BigInteger p = new BigInteger(buf);
			if (p.isProbablePrime(100)) {
				return p;
			}
		}
	}
}
