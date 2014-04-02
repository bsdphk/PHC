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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>A {@code Makwa} instance implements the Makwa password hashing
 * function. It is a context structure which contains some useful
 * parameters.</p>
 *
 * <p>The Makwa password hashing function uses as input a "password"
 * (actually an arbitrary sequence of bytes) and produces a binary output.
 * The parameters for this processing are the following:</p>
 * <ul>
 * <li><strong>Modulus:</strong> a big integer of at least 1273 bits, at
 * most 32768 bits. It is a composite integer, product of two prime
 * integers; the two primes constitute the <strong>private key</strong>;
 * Makwa can use either the modulus or the private key; processing with
 * the private key is faster, and unlocks some features such as
 * unescrowing.</li>
 * <li><strong>Hash function:</strong> a hash function is used internally,
 * and is identified by a symbolic constant. The value 0 selects the default
 * function, which is SHA-256.</li>
 * <li><strong>Salt:</strong> an arbitary sequence of bytes. Salts should
 * strive to achieve worldwide uniqueness. This implementation generates
 * 16-byte salts which are serialized UUID.
 * <li><strong>Pre-hashing:</strong> a boolean flag. If pre-hashing is
 * applied, then inputs can have an arbitrary length; however, pre-hashing
 * is not compatible with unescrow.</li>
 * <li><strong>Post-hashing length:</strong> the requested output length.
 * If that length is set to 0, then the Makwa output is the <em>primary
 * output</em>: the encoding of an integer, as long as the modulus. If
 * post-hashing is applied, then the binary output will consist of
 * exactly that many unbiased bytes, suitable for usage as key for
 * a symmetric cryptographic algorithm. Post-hashing allows for a shorter
 * and unbiased output; however, it prevents offline work factor changes
 * and unescrow.</li>
 * <li><strong>Work factor:</strong> the internal number of iterations
 * (repeated modular squarings). The processing time (without the private
 * key) is proportional to the work factor. The work factor must be
 * a nonnegative integer.</li>
 * </ul>
 *
 * <p>The Makwa output can be optionally <strong>encoded as a character
 * string</strong> as is described in section A.4 of the Makwa
 * specification. Such a string also contains the salt value, whether
 * pre-hashing and/or post-hashing were applied, the work factor, and a
 * checksum for the modulus and hash function. When the Makwa output is
 * a string, the following restrictions apply:</p>
 * <ul>
 * <li>The post-hashing length must be either 0 (no post hashing) or
 * an integer greater than or equal to 10 bytes.</li>
 * <li>The work factor must be equal to 2 or 3 multiplied by a power of
 * 2. The smallest acceptable work factors are 2, 3, 4, 6, 8, 12, 16,
 * 24, 32...</li>
 * </ul>
 *
 * <p>The modulus can be provided as a {@link BigInteger}, while the
 * private key can be represented as a {@link MakwaPrivateKey} instance.
 * Both modulus and private key can be encoded into bytes, using a format
 * described in the {@link MakwaPrivateKey} class comments.</p>
 *
 * <p>A {@code Makwa} instance contains the following parameters:</p>
 * <ul>
 * <li>the modulus;</li>
 * <li>optionally, the private key;</li>
 * <li>the hash function to use;</li>
 * <li>whether pre-hashing should be applied by default;</li>
 * <li>whether post-hashing should be applied by default, and, if yes,
 * the default output length (in bytes);</li>
 * <li>the default work factor.</li>
 * </ul>
 *
 * <p>These parameters shall comply to the "character string"
 * restrictions. They are used with the "simple API". That API is what
 * most users of Makwa should use:</p>
 * <ul>
 * <li>{@link #hashNewPassword}: hash a password into an encoded string.
 * The password is internally encoded into bytes using UTF-8. A new salt
 * is generated. The configured modulus, hash function, pre- and
 * post-hashing parameters, and work factor, are used for this
 * hashing.</li>
 * <li>{@link #verifyPassword}: verify a password with regards to the
 * provided reference output string.</li>
 * <li>{@link #setNewWorkFactor}: modify an output string to increase
 * or decrease its work factor. This method is applicable only if no
 * post-hashing was applied. Decrease is possible only if the context
 * was initialized with a private key.</li>
 * <li>{@link #unescrow(String)}: recover the source password. This is
 * possible only if no pre- or post-hashing was applied, and the context
 * was initialized with a private key.</li>
 * </ul>
 *
 * <p>Other methods are provided, which use only the modulus (or private
 * key) and hash function, but ignore the other initialization
 * parameters. The pre-hashing, post-hashing length, and work factors are
 * provided explicitly when required:</p>
 * <ul>
 * <li>{@link #doHash}: compute Makwa with explicit input, salt,
 * pre-hashing, post-hashing length, and work factor.</li>
 * <li>{@link #doHashToString}: same as {@link #doHash}, and the output
 * is encoded into the character string format used by
 * {@link #hashNewPassword}.</li>
 * <li>{@link #changeWorkFactor}: modify the work factor; the work
 * factor <em>difference</em> is given as parameter. A negative work
 * factor difference is allowed if the context was initialized with a
 * private key.</li>
 * <li>{@link #unescrow(byte[], byte[], int)}: recover the source
 * password. The salt and work factor must be provided explicitly.
 * This recovery works only if a private key is known.</li>
 * </ul>
 *
 * <p>The {@code doKDF()} methods give a direct access to the internal
 * KDF. These are static methods, usable without context initialization.</p>
 *
 * <p>Each {@code Makwa} instance is thread-safe and immutable.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class Makwa {

	/**
	 * Symbolic constant designating hash function SHA-256.
	 */
	public static final int SHA256 = 1;

	/**
	 * Symbolic constant designating hash function SHA-512.
	 */
	public static final int SHA512 = 2;

	private BigInteger modulus;
	private int hashFunction;
	private boolean defaultPreHash;
	private int defaultPostHashLength;
	private int defaultWorkFactor;
	private MakwaPrivateKey privateKey;
	private byte[] modulusID;

	/**
	 * <p>Create a new instance, using the provided modulus, underlying
	 * hash function (a symbolic constant, e.g. {@code Makwa.SHA256}),
	 * where pre-hashing should be applied, the requested output
	 * length (10 bytes or more; or 0 to apply no post-hashing),
	 * and the default work factor. The default parameters are those
	 * applied by {@link #hashNewPassword}. The default work factor
	 * must be "encodable" (equal to 2 or 3 times a power of 2).</p>
	 *
	 * <p>If {@code hashFunction} is 0, then the default hash function
	 * (SHA-256) is used. If {@code defaultWorkFactor} is used, then
	 * a work factor of value 4096 is used.</p>
	 *
	 * @param modulus                 the modulus
	 * @param hashFunction            the underlying hash function
	 * @param defaultPreHash          whether pre-hashing must be applied
	 * @param defaultPostHashLength   post-hash length (10 or more), or 0
	 * @param defaultWorkFactor       default work factor
	 * @throws MakwaException  on invalid parameters
	 */
	public Makwa(BigInteger modulus, int hashFunction,
		boolean defaultPreHash, int defaultPostHashLength,
		int defaultWorkFactor)
	{
		init(modulus, hashFunction, defaultPreHash,
			defaultPostHashLength, defaultWorkFactor);
	}

	/**
	 * <p>Create a new instance, using the provided private key,
	 * underlying hash function (a symbolic constant, e.g. {@code
	 * Makwa.SHA256}), where pre-hashing should be applied, the
	 * requested output length (10 bytes or more; or 0 to apply no
	 * post-hashing), and the default work factor. The default
	 * parameters are those applied by {@link #hashNewPassword}.
	 * The default work factor must be "encodable" (equal to 2 or 3
	 * times a power of 2). A context with a known private key
	 * allows for faster computations ("fast path"), unescrow,
	 * and work factor decrease.</p>
	 *
	 * <p>If {@code hashFunction} is 0, then the default hash function
	 * (SHA-256) is used. If {@code defaultWorkFactor} is used, then
	 * a work factor of value 4096 is used.</p>
	 *
	 * @param privateKey              the private key
	 * @param hashFunction            the underlying hash function
	 * @param defaultPreHash          whether pre-hashing must be applied
	 * @param defaultPostHashLength   post-hash length (10 or more), or 0
	 * @param defaultWorkFactor       default work factor
	 * @throws MakwaException  on invalid parameters
	 */
	public Makwa(MakwaPrivateKey privateKey, int hashFunction,
		boolean defaultPreHash, int defaultPostHashLength,
		int defaultWorkFactor)
	{
		init(privateKey, hashFunction, defaultPreHash,
			defaultPostHashLength, defaultWorkFactor);
	}

	/**
	 * <p>Create a new instance, using the provided parameter,
	 * underlying hash function (a symbolic constant, e.g. {@code
	 * Makwa.SHA256}), where pre-hashing should be applied, the
	 * requested output length (10 bytes or more; or 0 to apply no
	 * post-hashing), and the default work factor. The default
	 * parameters are those applied by {@link #hashNewPassword}.
	 * The default work factor must be "encodable" (equal to 2 or 3
	 * times a power of 2).</p>
	 *
	 * <p>The "parameter" is an encoded modulus, a Makwa private
	 * key, or a set of delegation parameters (of which only the
	 * modulus part is used); if a private key is used, then the
	 * relevant features are unlocked: fast processing ("fast
	 * path"), unescrow, and work factor decrease.</p>
	 *
	 * <p>If {@code hashFunction} is 0, then the default hash function
	 * (SHA-256) is used. If {@code defaultWorkFactor} is used, then
	 * a work factor of value 4096 is used.</p>
	 *
	 * @param param                   the modulus or private key
	 * @param hashFunction            the underlying hash function
	 * @param defaultPreHash          whether pre-hashing must be applied
	 * @param defaultPostHashLength   post-hash length (10 or more), or 0
	 * @param defaultWorkFactor       default work factor
	 * @throws MakwaException  on invalid parameters
	 */
	public Makwa(byte[] param, int hashFunction,
		boolean defaultPreHash, int defaultPostHashLength,
		int defaultWorkFactor)
	{
		try {
			InputStream in = new ByteArrayInputStream(param);
			int magic = MakwaIO.read32(in);
			switch (magic) {
			case MakwaIO.MAGIC_PUBKEY:
				BigInteger mod = MakwaIO.readMPI(in);
				checkEOF(in);
				init(mod, hashFunction, defaultPreHash,
					defaultPostHashLength,
					defaultWorkFactor);
				break;
			case MakwaIO.MAGIC_PRIVKEY:
				init(new MakwaPrivateKey(param), hashFunction,
					defaultPreHash, defaultPostHashLength,
					defaultWorkFactor);
				break;
			case MakwaIO.MAGIC_DELEG_PARAM:
				BigInteger mod2 = MakwaIO.readMPI(in);
				init(mod2, hashFunction, defaultPreHash,
					defaultPostHashLength,
					defaultWorkFactor);
				break;
			default:
				throw new MakwaException(
					"unknown Makwa parameter type");
			}
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid Makwa parameter (truncated)");
		}
	}

	private static void checkEOF(InputStream in)
		throws IOException
	{
		if (in.read() >= 0) {
			throw new MakwaException(
				"invalid Makwa parameter (trailing garbage)");
		}
	}

	private void init(BigInteger modulus, int hashFunction,
		boolean defaultPreHash, int defaultPostHashLength,
		int defaultWorkFactor)
	{
		if (hashFunction == 0) {
			hashFunction = SHA256;
		}
		if (defaultWorkFactor == 0) {
			defaultWorkFactor = 4096;
		}
		this.modulus = modulus;
		this.hashFunction = hashFunction;
		this.defaultPreHash = defaultPreHash;
		this.defaultPostHashLength = defaultPostHashLength;
		this.defaultWorkFactor = defaultWorkFactor;

		if (modulus.signum() <= 0 || modulus.bitLength() < 1273
			|| (modulus.intValue() & 3) != 1)
		{
			throw new MakwaException("invalid modulus");
		}
		if (defaultPostHashLength < 0
			|| (defaultPostHashLength > 0
			&& defaultPostHashLength < 10))
		{
			throw new MakwaException("invalid post-hash length");
		}
		if (defaultWorkFactor <= 0) {
			throw new MakwaException("invalid default work factor");
		}

		// This call checks that the work factor has the expected
		// format: 2 or 3 times a power of 2.
		getWFMant(defaultWorkFactor);

		modulusID = new byte[8];
		doKDF(hashFunction, I2OSP(modulus),
			modulusID, 0, modulusID.length);
	}

	private void init(MakwaPrivateKey privateKey, int hashFunction,
		boolean defaultPreHash, int defaultPostHashLength,
		int defaultWorkFactor)
	{
		init(privateKey.getModulus(), hashFunction,
			defaultPreHash, defaultPostHashLength,
			defaultWorkFactor);
		this.privateKey = privateKey;
	}

	/**
	 * Hash a new password. The default parameters (pre-hashing,
	 * post-hashing length, work factor) are applied. A new 16-byte
	 * salt is internally generated. The returned string contains
	 * the parameters and salt.
	 *
	 * @param pwd   the new password
	 * @return  the hashed password (encoded
	 * @throws MakwaException  on error
	 */
	public String hashNewPassword(String pwd)
	{
		byte[] pi = encodePassword(pwd);
		byte[] salt = createSalt();
		return doHashToString(pi, salt, defaultPreHash,
			defaultPostHashLength, defaultWorkFactor);
	}

	/**
	 * Verify a password against a string previously produced with
	 * {@code hashNewPassword}. If the reference string is unsuitable
	 * in some way (e.g. bad encoding, or using a modulus other than
	 * the one used for this context), then an exception is thrown.
	 * If the reference string is proper but the password does not
	 * match, then {@code false} is returned.
	 *
	 * @param pwd   the password to verify
	 * @param ref   the reference string (hashed password)
	 * @return  {@code true} on correct password
	 * @throws MakwaException  on format error
	 */
	public boolean verifyPassword(String pwd, String ref)
	{
		byte[] pi = encodePassword(pwd);
		Output mo = new Output(ref);
		byte[] out = doHash(pi, mo.getSalt(), mo.getPreHash(),
			mo.getPostHashLength(), mo.getWorkFactor());
		return equals(out, mo.getTau());
	}

	/**
	 * Set the work factor for a given Makwa output string to a
	 * new value. The new output string is returned. The new work
	 * factor value must be encodable (equal to 2 or 3 times a
	 * power of 2). This method can work only if the {@code ref}
	 * string was produced without post-hashing; moreover, the
	 * work factor can be decreased only if this instance was
	 * initialized with a private key.
	 *
	 * @param ref             the source Makwa output string
	 * @param newWorkFactor   the new work factor value
	 * @return  the transformed Makwa output string
	 * @throws MakwaException  on invalid parameters or format error
	 */
	public String setNewWorkFactor(String ref, int newWorkFactor)
	{
		// Verify that the new work factor can be encoded
		// in an output string.
		getWFMant(newWorkFactor);

		// Parse the string.
		Output mo = new Output(ref);
		if (mo.getPostHashLength() != 0) {
			throw new MakwaException("cannot change work"
				+ " factor: post-hashing applied");
		}

		// Compute new output and reencode it.
		byte[] out = changeWorkFactor(mo.getTau(),
			newWorkFactor - mo.getWorkFactor());
		mo = new Output(mo.getSalt(), mo.getPreHash(), 0,
			newWorkFactor, out);
		return mo.toString();
	}

	/**
	 * Create a new salt value. This method returns an encoded UUID,
	 * which should ensure worldwide uniqueness with very high
	 * probability.
	 *
	 * @return  a new salt value
	 */
	public static byte[] createSalt()
	{
		UUID uu = UUID.randomUUID();
		long v0 = uu.getMostSignificantBits();
		long v1 = uu.getLeastSignificantBits();
		byte[] salt = new byte[16];
		for (int i = 0; i < 8; i ++) {
			salt[i] = (byte)(v0 >>> (56 - (i << 3)));
			salt[i + 8] = (byte)(v1 >>> (56 - (i << 3)));
		}
		return salt;
	}

	/**
	 * Apply Makwa on the provided parameters: input (already encoded
	 * as bytes), salt, optional pre-hashing, post-hashing length,
	 * and work factor.
	 *
	 * @param input            the encoded input
	 * @param salt             the salt value
	 * @param preHash          {@code true} to apply pre-hashing
	 * @param postHashLength   the requested output length (0 for no
	 *                         post-hashing; the output then has the
	 *                         same length as the modulus)
	 * @param workFactor       the work factor (nonnegative)
	 * @return  the Makwa binary output
	 * @throws MakwaException  on error
	 */
	public byte[] doHash(byte[] input, byte[] salt, boolean preHash,
		int postHashLength, int workFactor)
	{
		// Pre-hash input, if applicable.
		if (preHash) {
			byte[] tmp = new byte[64];
			doKDF(hashFunction, input, tmp, 0, tmp.length);
			input = tmp;
		}

		// Compute padding and write it into X[].
		int k = (modulus.bitLength() + 7) >> 3;
		byte[] X = new byte[k];
		int u = input.length;
		if (u > 255 || u > (k - 32)) {
			throw new MakwaException("oversized input");
		}
		byte[] padIn = new byte[salt.length + u + 1];
		System.arraycopy(salt, 0, padIn, 0, salt.length);
		System.arraycopy(input, 0, padIn, salt.length, u);
		padIn[salt.length + u] = (byte)u;
		doKDF(hashFunction, padIn, X, 1, k - 2 - u);

		// Copy input and length into X[].
		System.arraycopy(input, 0, X, k - u - 1, u);
		X[k - 1] = (byte)u;

		// Reinterpret X[] as an integer and compute y.
		BigInteger x = OS2IP(X);
		BigInteger y = multiSquare(x, workFactor + 1);

		// Encode y into Y[]
		byte[] Y = I2OSP(y);

		// Do post-hashing if requested.
		if (postHashLength > 0) {
			byte[] out = new byte[postHashLength];
			doKDF(hashFunction, Y, out, 0, out.length);
			return out;
		} else {
			return Y;
		}
	}

	/**
	 * Apply Makwa on the provided parameters: input (already encoded
	 * as bytes), salt, optional pre-hashing, post-hashing length,
	 * and work factor. The output is returned as an encoded string;
	 * the work factor must then be "encodable", and the post-hashing
	 * length (if non-zero) must be at least 10.
	 *
	 * @param input            the encoded input
	 * @param salt             the salt value
	 * @param preHash          {@code true} to apply pre-hashing
	 * @param postHashLength   the requested output length (0 for no
	 *                         post-hashing; the output then has the
	 *                         same length as the modulus)
	 * @param workFactor       the work factor (nonnegative)
	 * @return  the Makwa output (as a string)
	 * @throws MakwaException  on error
	 */
	public String doHashToString(byte[] input, byte[] salt,
		boolean preHash, int postHashLength, int workFactor)
	{
		getWFMant(workFactor);
		byte[] out = doHash(input, salt, preHash,
			postHashLength, workFactor);
		return encodeOutput(salt, preHash,
			postHashLength, workFactor, out);
	}

	/**
	 * Encode a Makwa output (already computed) into a string. The
	 * parameters used to compute the output must be specified. The
	 * work factor and post-hashing length must comply with the
	 * "string encoding" constraints. The binary output must be
	 * consistent with the parameters.
	 *
	 * @param salt             the salt value
	 * @param preHash          {@code true} to apply pre-hashing
	 * @param postHashLength   the requested output length (0 for no
	 *                         post-hashing; the output then has the
	 *                         same length as the modulus)
	 * @param workFactor       the work factor (nonnegative)
	 * @param output           the Makwa binary output
	 * @return  the string-encoded output
	 * @throws MakwaException  on error
	 */
	public String encodeOutput(byte[] salt, boolean preHash,
		int postHashLength, int workFactor, byte[] output)
	{
		return new Output(salt, preHash, postHashLength,
			workFactor, output).toString();
	}

	/**
	 * Decode a string-encoded Makwa output into its constituent
	 * elements (salt, pre-hashing flag, post-hashing length,
	 * work factor, and binary output). The provided string must
	 * match the modulus and hash function used by this instance.
	 *
	 * @param str   the output string to parse
	 * @return  the decoded output
	 * @throws MakwaException  on parse error
	 */
	public Output decodeOutput(String str)
	{
		return new Output(str);
	}

	/**
	 * Change the work factor on a given Makwa output. The provided
	 * output ({@code prev}) must have been produced without
	 * post-hashing. The difference between the new work factor and
	 * the previous one is provided as the {@code diffWF} parameter;
	 * if that value is negative then this is a work factor
	 * <em>decrease</em>, which is possible only if this instance was
	 * initialized with a private key.
	 *
	 * @param prev     the previous Makwa output (binary)
	 * @param diffWF   the work factor difference
	 * @return  the new Makwa output (binary)
	 * @throws MakwaException  on format error
	 */
	public byte[] changeWorkFactor(byte[] prev, int diffWF)
	{
		BigInteger y = OS2IP(prev);
		if (diffWF == 0) {
			return prev;
		}
		if (diffWF > 0) {
			return I2OSP(multiSquare(y, diffWF));
		} else {
			if (privateKey == null) {
				throw new MakwaException("cannot decrease"
					+ " work factor without private key");
			}
			BigInteger p = privateKey.getP();
			BigInteger q = privateKey.getQ();
			BigInteger ep = sqrtExp(p, -diffWF);
			BigInteger eq = sqrtExp(q, -diffWF);
			BigInteger yp = y.mod(p).modPow(ep, p);
			BigInteger yq = y.mod(q).modPow(eq, q);
			return I2OSP(doCRT(p, q, privateKey.getInvQ(), yp, yq));
		}
	}

	/**
	 * Recover the input (encoded password) from the provided Makwa
	 * output string. This method works only if a private key is
	 * known, and no pre- or post-hashing was applied.
	 *
	 * @param ref   the Makwa output string
	 * @return  the unescrowed input
	 * @throws MakwaException  on error
	 */
	public byte[] unescrow(String ref)
	{
		if (privateKey == null) {
			throw new MakwaException("cannot unescrow:"
				+ " no private key supplied");
		}
		Output mo = new Output(ref);
		if (mo.getPreHash()) {
			throw new MakwaException("cannot unescrow:"
				+ " pre-hashing applied");
		}
		if (mo.getPostHashLength() != 0) {
			throw new MakwaException("cannot unescrow:"
				+ " post-hashing applied");
		}
		return unescrow(mo.getTau(), mo.getSalt(), mo.getWorkFactor());
	}

	/**
	 * Recover the input (encoded password) from the provided Makwa
	 * output (binary). This method works only if a private key is
	 * known, and no pre- or post-hashing was applied. The salt and
	 * work factor must also be provided explicitly.
	 *
	 * @param output       the Makwa output string
	 * @param salt         the salt value
	 * @param workFactor   the work factor
	 * @return  the unescrowed input
	 * @throws MakwaException  on error
	 */
	public byte[] unescrow(byte[] output, byte[] salt, int workFactor)
	{
		if (privateKey == null) {
			throw new MakwaException("cannot unescrow:"
				+ " no private key supplied");
		}
		BigInteger y = OS2IP(output);
		BigInteger p = privateKey.getP();
		BigInteger q = privateKey.getQ();
		BigInteger iq = privateKey.getInvQ();
		BigInteger ep = sqrtExp(p, workFactor + 1);
		BigInteger eq = sqrtExp(q, workFactor + 1);
		BigInteger x1p = y.mod(p).modPow(ep, p);
		BigInteger x1q = y.mod(q).modPow(eq, q);
		BigInteger x2p = p.subtract(x1p).mod(p);
		BigInteger x2q = q.subtract(x1q).mod(q);

		BigInteger[] xc = new BigInteger[4];
		xc[0] = doCRT(p, q, iq, x1p, x1q);
		xc[1] = doCRT(p, q, iq, x1p, x2q);
		xc[2] = doCRT(p, q, iq, x2p, x1q);
		xc[3] = doCRT(p, q, iq, x2p, x2q);
		loop: for (int i = 0; i < 4; i ++) {
			byte[] buf = I2OSP(xc[i]);
			int k = buf.length;
			if (buf[0] != 0x00) {
				continue;
			}
			int u = buf[k - 1] & 0xFF;
			if (u > (k - 32)) {
				continue;
			}
			byte[] tmp = new byte[salt.length + u + 1];
			System.arraycopy(salt, 0, tmp, 0, salt.length);
			System.arraycopy(buf, k - 1 - u,
				tmp, salt.length, u + 1);
			byte[] S = new byte[k - u - 2];
			doKDF(hashFunction, tmp, S, 0, S.length);
			for (int j = 0; j < S.length; j ++) {
				if (S[j] != buf[j + 1]) {
					continue loop;
				}
			}
			byte[] pi = new byte[u];
			System.arraycopy(buf, k - 1 - u, pi, 0, u);
			return pi;
		}
		throw new MakwaException("unescrow failed");
	}

	/**
	 * Begin delegated application of Makwa on some input value. The
	 * returned context contains the values which are to be sent to
	 * the delegation server, and can finalize the hash value when
	 * that server returns a value.
	 *
	 * @param input            the encoded input
	 * @param salt             the salt value
	 * @param preHash          {@code true} to apply pre-hashing
	 * @param postHashLength   the requested output length (0 for no
	 *                         post-hashing; the output then has the
	 *                         same length as the modulus)
	 * @param mdeleg           the delegation parameters
	 * @return  the delegation context
	 * @throws MakwaException  on error
	 */
	public DelegationContext doHashDelegate(byte[] input,
		byte[] salt, boolean preHash, int postHashLength,
		MakwaDelegation mdeleg)
	{
		if (!modulus.equals(mdeleg.getModulus())) {
			throw new MakwaException(
				"modulus mismatch for delegation");
		}
		byte[] X2 = doHash(input, salt, preHash, 0, 0);
		return new DelegationContext(mdeleg, OS2IP(X2),
			salt, preHash, postHashLength);
	}

	/**
	 * Begin delegated application of Makwa on some input password.
	 * This is for a new hash value; a new salt value is internally
	 * generated. The returned context contains the values which are
	 * to be sent to the delegation server, and can finalize the
	 * hash value when that server returns a value. The pre-hashing,
	 * post-hashing length and work factors used to initialize this
	 * {@code Makwa} instance are used.
	 *
	 * @param pwd      the password to hash
	 * @param mdeleg   the delegation parameters
	 * @return  the delegation context
	 * @throws MakwaException  on error
	 */
	public DelegationContext hashNewPasswordDelegate(
		String pwd, MakwaDelegation mdeleg)
	{
		return doHashDelegate(encodePassword(pwd), createSalt(),
			defaultPreHash, defaultPostHashLength, mdeleg);
	}

	/**
	 * <p>Begin delegated application of Makwa on some input
	 * password. This is for verifying the password; the provided
	 * reference string is used to obtain the hash parameters (salt,
	 * pre-hashing, post-hashing length, work factor). The returned
	 * context contains the values which are to be sent to the
	 * delegation server, and can finalize the verification when
	 * that server returns a value.</p>
	 *
	 * <p>Several sets of delegation parameters can be provided;
	 * the first one which matches the reference string will be used.
	 * The intended use case is when a system manages hashed passwords
	 * with non-homogenous work factors.</p>
	 *
	 * @param pwd       the password to hash
	 * @param ref       the reference hash value to compare with
	 * @param mdelegs   the sets of delegation parameters
	 * @return  the delegation context
	 * @throws MakwaException  on error
	 */
	public DelegationContext verifyPasswordDelegate(
		String pwd, String ref, MakwaDelegation... mdelegs)
	{
		Output mo = new Output(ref);
		int workFactor = mo.getWorkFactor();
		for (MakwaDelegation md : mdelegs) {
			if (md.getWorkFactor() != workFactor) {
				continue;
			}
			if (!md.getModulus().equals(modulus)) {
				continue;
			}
			DelegationContext dc = doHashDelegate(
				encodePassword(pwd),
				mo.getSalt(), mo.getPreHash(),
				mo.getPostHashLength(), md);
			dc.setRefTau(mo.getTau());
			return dc;
		}
		throw new MakwaException("no matching delegation parameters");
	}

	BigInteger parseDelegationAnswer(byte[] answer)
	{
		try {
			ByteArrayInputStream in =
				new ByteArrayInputStream(answer);
			int magic = MakwaIO.read32(in);
			if (magic != MakwaIO.MAGIC_DELEG_ANS) {
				throw new MakwaException(
					"unknown delegation answer type");
			}
			BigInteger msq = MakwaIO.readMPI(in);
			checkEOF(in);
			if (msq.signum() <= 0 || msq.compareTo(modulus) >= 0) {
				throw new MakwaException("invalid delegation"
					+ " answer (out of range)");
			}
			return msq;
		} catch (IOException ioe) {
			throw new MakwaException("invalid answer from"
				+ " delegation server (truncated)");
		}
	}

	/**
	 * An instance of this class represents a delegated Makwa
	 * computation. It contains the parameters which must be sent
	 * to the delegation server: modulus, value to square repeatedly,
	 * and number of squarings (the work factor). When the delegation
	 * server returns its answer (a big integer), the final hash value
	 * can be obtained (as bytes, or as an encoded string).
	 */
	public class DelegationContext {

		private byte[] salt;
		private boolean preHash;
		private int workFactor;
		private int postHashLength;
		private BigInteger maskedX, unmask;
		private byte[] refTau;

		private DelegationContext(MakwaDelegation mdeleg,
			BigInteger x2, byte[] salt,
			boolean preHash, int postHashLength)
		{
			this.salt = salt;
			this.preHash = preHash;
			this.postHashLength = postHashLength;
			BigInteger[] maskPair = mdeleg.createMaskPair();
			maskedX = x2.multiply(maskPair[0]).mod(getModulus());
			unmask = maskPair[1];
			workFactor = mdeleg.getWorkFactor();
		}

		void setRefTau(byte[] refTau)
		{
			this.refTau = refTau;
		}

		/**
		 * Get the Makwa modulus.
		 *
		 * @return  the modulus
		 */
		BigInteger getModulus()
		{
			return Makwa.this.modulus;
		}

		/**
		 * Get the value which should be repeatedly squared.
		 *
		 * @return  the value
		 */
		BigInteger getValue()
		{
			return maskedX;
		}

		/**
		 * Get the work factor.
		 *
		 * @return  the work factor
		 */
		int getWorkFactor()
		{
			return workFactor;
		}

		/**
		 * Serialize this context into a request to send to the
		 * delegation server.
		 *
		 * @return  the request
		 */
		public byte[] getRequest()
		{
			try {
				ByteArrayOutputStream out =
					new ByteArrayOutputStream();
				MakwaIO.write32(out, MakwaIO.MAGIC_DELEG_REQ);
				MakwaIO.writeMPI(out, getModulus());
				MakwaIO.write32(out, getWorkFactor());
				MakwaIO.writeMPI(out, getValue());
				return out.toByteArray();
			} catch (IOException ioe) {
				// Cannot actually happen.
				throw new MakwaException(ioe);
			}
		}

		/**
		 * Using the value returned by the delegation server,
		 * finalize the Makwa computation.
		 *
		 * @param answer   the answer from the delegation server
		 * @return  the Makwa output (binary)
		 * @throws MakwaException  on error
		 */
		public byte[] doFinal(byte[] answer)
		{
			return doFinal(parseDelegationAnswer(answer));
		}

		byte[] doFinal(BigInteger msqValue)
		{
			BigInteger mod = getModulus();
			if (msqValue.signum() <= 0
				|| msqValue.compareTo(mod) >= 0)
			{
				throw new MakwaException("invalid answer"
					+ " from delegation server");
			}
			BigInteger y = msqValue.multiply(unmask)
				.mod(getModulus());
			byte[] tau = I2OSP(y);
			if (postHashLength > 0) {
				byte[] out = new byte[postHashLength];
				doKDF(hashFunction, tau, out, 0, out.length);
				tau = out;
			}
			return tau;
		}

		/**
		 * Using the value returned by the delegation server,
		 * finalize the Makwa computation. The value is returned
		 * in string encoding. This method works only if the
		 * work factor is "encodable" (equal to 2 or 3 times a
		 * power of 2).
		 *
		 * @param answer   the answer from the delegation server
		 * @return  the Makwa output (string)
		 * @throws MakwaException  on error
		 */
		public String doFinalToString(byte[] answer)
		{
			return doFinalToString(parseDelegationAnswer(answer));
		}

		String doFinalToString(BigInteger msqValue)
		{
			byte[] tau = doFinal(msqValue);
			Output mo = new Output(salt, preHash,
				postHashLength, workFactor, tau);
			return mo.toString();
		}

		/**
		 * Using the value returned by the delegation server,
		 * finalize the Makwa computation for a password
		 * verification. This method shall be called only if this
		 * context instance was created with
		 * {@link Makwa#verifyPasswordDelegate}.
		 *
		 * @param answer   the answer from the delegation server
		 * @return  {@code true} on correct password
		 * @throws MakwaException  on error
		 */
		public boolean doFinalVerify(byte[] answer)
		{
			return doFinalVerify(parseDelegationAnswer(answer));
		}

		boolean doFinalVerify(BigInteger msqValue)
		{
			if (refTau == null) {
				throw new MakwaException("illegal state:"
					+ " context was not created for"
					+ " verification");
			}
			byte[] tau = doFinal(msqValue);
			return Makwa.equals(tau, refTau);
		}
	}

	/**
	 * Parse a delegation request, and compute the answer. This static
	 * method is what a delegation server may use.
	 *
	 * @param req   the delegation request
	 * @return  the encoded answer
	 * @throws MakwaException  on error
	 */
	public static byte[] processDelegationRequest(byte[] req)
	{
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(req);
			if (MakwaIO.read32(in) != MakwaIO.MAGIC_DELEG_REQ) {
				throw new MakwaException("unknown delegation"
					+ " request type");
			}
			BigInteger mod = MakwaIO.readMPI(in);
			int wf = MakwaIO.read32(in);
			BigInteger v = MakwaIO.readMPI(in);
			checkEOF(in);
			BigInteger v2 = multiSquare(v, wf, mod);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			MakwaIO.write32(out, MakwaIO.MAGIC_DELEG_ANS);
			MakwaIO.writeMPI(out, v2);
			return out.toByteArray();
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid delegation request (truncated)");
		}
	}

	/**
	 * Repeatedly apply modular squaring on some integer. This static
	 * method is what a delegation server may use.
	 *
	 * @param v     the value to square repeatedly
	 * @param wf    the number of squarings (work factor)
	 * @param mod   the modulus
	 * @return  the result
	 * @throws MakwaException  on error
	 */
	static BigInteger multiSquare(
		BigInteger v, int wf, BigInteger mod)
	{
		if (mod.signum() <= 0 || (mod.intValue() & 3) != 1) {
			throw new MakwaException("invalid modulus");
		}
		if (wf < 0) {
			throw new MakwaException("negative work factor");
		}
		if (v.signum() <= 0 || v.compareTo(mod) >= 0) {
			throw new MakwaException(
				"invalid value (out of range)");
		}

		/*
		 * We use BigInteger.modPow() to avoid most modular
		 * reductions; that method is supposed to be optimized.
		 */
		int step = mod.bitLength();
		while (wf > 0) {
			int z = Math.min(wf, step);
			v = v.modPow(BigInteger.ONE.shiftLeft(z), mod);
			wf -= z;
		}
		return v;
	}

	/* =============================================================== */

	/*
	 * Compute the exponent for reverting w squarings modulo prime p.
	 */
	private static BigInteger sqrtExp(BigInteger p, int w)
	{
		BigInteger e = p.add(BigInteger.ONE).shiftRight(2);
		return e.modPow(BigInteger.valueOf(w),
			p.subtract(BigInteger.ONE));
	}

	/*
	 * Apply CRT on zp and zq, for primes p and q; iq is the
	 * inverse of q modulo p.
	 */
	private static BigInteger doCRT(BigInteger p, BigInteger q,
		BigInteger iq, BigInteger zp, BigInteger zq)
	{
		BigInteger h = zp.subtract(zq).multiply(iq).mod(p);
		BigInteger z = zq.add(q.multiply(h));
		return z;
	}

	BigInteger multiSquare(BigInteger x, int w)
	{
		/*
		 * If there is a known private key and the work factor
		 * is big enough, then we use the private key and the
		 * CRT. Threshold has been empirically set at 34% of the
		 * modulus length (in bits).
		 */
		if (privateKey != null
			&& w >= (modulus.bitLength() * 34 + 50) / 100)
		{
			BigInteger p = privateKey.getP();
			BigInteger q = privateKey.getQ();
			BigInteger two = BigInteger.valueOf(2);
			BigInteger bw = BigInteger.valueOf(w);
			BigInteger ep = two.modPow(
				bw, p.subtract(BigInteger.ONE));
			BigInteger eq = two.modPow(
				bw, q.subtract(BigInteger.ONE));
			BigInteger yp = x.mod(p).modPow(ep, p);
			BigInteger yq = x.mod(q).modPow(eq, q);
			return doCRT(p, q, privateKey.getInvQ(), yp, yq);
		}

		/*
		 * If there is no known private key, or the work factor
		 * is too small, then we fall back on the generic method.
		 */
		return multiSquare(x, w, modulus);
	}

	BigInteger getModulus()
	{
		return modulus;
	}

	byte[] getModulusID()
	{
		return modulusID;
	}

	private static byte[] encodePassword(String password)
	{
		try {
			return password.getBytes("UTF-8");
		} catch (IOException ioe) {
			// This cannot happen in practice, since all
			// JVM are supposed to support UTF-8.
			throw new Error(ioe);
		}
	}

	/**
	 * Compute the Makwa KDF over the provided input. The {@code hash}
	 * parameter is the symbolic identifier for the underlying hash
	 * function.
	 *
	 * @param hash     the underlying hash function
	 * @param inBuf    the input data buffer
	 * @param outBuf   the output buffer
	 */
	public static void doKDF(int hash, byte[] inBuf, byte[] outBuf)
	{
		doKDF(hash, inBuf, 0, inBuf.length, outBuf, 0, outBuf.length);
	}

	/**
	 * Compute the Makwa KDF over the provided input. The {@code hash}
	 * parameter is the symbolic identifier for the underlying hash
	 * function.
	 *
	 * @param hash     the underlying hash function
	 * @param inBuf    the input data buffer
	 * @param outBuf   the output buffer
	 * @param outOff   the output offset
	 * @param outLen   the output length
	 */
	public static void doKDF(int hash, byte[] inBuf,
		byte[] outBuf, int outOff, int outLen)
	{
		doKDF(hash, inBuf, 0, inBuf.length, outBuf, outOff, outLen);
	}

	/**
	 * Compute the Makwa KDF over the provided input. The {@code hash}
	 * parameter is the symbolic identifier for the underlying hash
	 * function.
	 *
	 * @param hash     the underlying hash function
	 * @param inBuf    the input data buffer
	 * @param inOff    the input data offset
	 * @param inLen    the input data length
	 * @param outBuf   the output buffer
	 */
	public static void doKDF(int hash, byte[] inBuf, int inOff, int inLen,
		byte[] outBuf)
	{
		doKDF(hash, inBuf, inOff, inLen, outBuf, 0, outBuf.length);
	}

	/**
	 * Compute the Makwa KDF over the provided input. The {@code hash}
	 * parameter is the symbolic identifier for the underlying hash
	 * function.
	 *
	 * @param hash     the underlying hash function
	 * @param inBuf    the input data buffer
	 * @param inOff    the input data offset
	 * @param inLen    the input data length
	 * @param outBuf   the output buffer
	 * @param outOff   the output offset
	 * @param outLen   the output length
	 */
	public static void doKDF(int hash, byte[] inBuf, int inOff, int inLen,
		byte[] outBuf, int outOff, int outLen)
	{
		try {
			doKDFInner(hash, inBuf, inOff, inLen,
				outBuf, outOff, outLen);
		} catch (NoSuchAlgorithmException nsae) {
			throw new MakwaException(nsae);
		} catch (InvalidKeyException ike) {
			throw new MakwaException(ike);
		}
	}

	private static void doKDFInner(int hash,
		byte[] inBuf, int inOff, int inLen,
		byte[] outBuf, int outOff, int outLen)
		throws NoSuchAlgorithmException, InvalidKeyException
	{
		int digLen;
		String macName;
		switch (hash) {
		case SHA256:
			digLen = 32;
			macName = "HmacSHA256";
			break;
		case SHA512:
			digLen = 64;
			macName = "HmacSHA512";
			break;
		default:
			throw new MakwaException(
				"unknown hash function type: " + hash);
		}
		Mac mac = Mac.getInstance(macName);
		int r = mac.getMacLength();
		if (r != digLen) {
			throw new MakwaException(
				"unexpected HMAC output length: " + r);
		}

		// 1. V <- 0x01 0x01 ... 0x01
		byte[] V = new byte[r];
		for (int i = 0; i < r; i ++) {
			V[i] = 0x01;
		}

		// 2. K <- 0x00 0x00 ... 0x00
		byte[] K = new byte[r];
		mac.init(new SecretKeySpec(K, macName));

		// 3. K <- HMAC_K(V || 0x00 || m)
		mac.update(V);
		mac.update((byte)0x00);
		mac.update(inBuf, inOff, inLen);
		K = mac.doFinal();
		mac.init(new SecretKeySpec(K, macName));

		// 4. V <- HMAC_K(V)
		mac.update(V);
		V = mac.doFinal();

		// 5. K <- HMAC_K(V || 0x01 || m)
		mac.update(V);
		mac.update((byte)0x01);
		mac.update(inBuf, inOff, inLen);
		K = mac.doFinal();
		mac.init(new SecretKeySpec(K, macName));

		// 6. V <- HMAC_K(V)
		mac.update(V);
		V = mac.doFinal();

		// 7. and 8.: repeat V <- HMAC_K(V)
		while (outLen > 0) {
			mac.update(V);
			V = mac.doFinal();
			int clen = Math.min(r, outLen);
			System.arraycopy(V, 0, outBuf, outOff, clen);
			outOff += clen;
			outLen -= clen;
		}
	}

	byte[] I2OSP(BigInteger x)
	{
		int len = (modulus.bitLength() + 7) >> 3;
		byte[] b = x.toByteArray();
		int blen = b.length;
		if (blen < len) {
			byte[] nb = new byte[len];
			System.arraycopy(b, 0, nb, len - blen, blen);
			return nb;
		} else if (blen == len) {
			return b;
		} else {
			byte[] nb = new byte[len];
			System.arraycopy(b, blen - len, nb, 0, len);
			return nb;
		}
	}

	BigInteger OS2IP(byte[] b)
	{
		int len = (modulus.bitLength() + 7) >> 3;
		if (b.length != len) {
			throw new MakwaException("invalid integer input");
		}
		if (b[0] < 0) {
			int blen = b.length;
			byte[] nb = new byte[blen + 1];
			System.arraycopy(b, 0, nb, 1, blen);
			b = nb;
		}
		BigInteger x = new BigInteger(1, b);
		if (x.compareTo(modulus) >= 0) {
			throw new MakwaException("invalid integer input");
		}
		return x;
	}

	private static boolean equals(byte[] b1, byte[] b2)
	{
		if (b1 == b2) {
			return true;
		}
		if (b1 == null || b2 == null) {
			return false;
		}
		int n = b1.length;
		if (n != b2.length) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			if (b1[i] != b2[i]) {
				return false;
			}
		}
		return true;
	}

	private static String BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		+ "abcdefghijklmnopqrstuvwxyz0123456789+/";

	static String base64Encode(byte[] buf, boolean withEqual)
	{
		return base64Encode(buf, 0, buf.length, withEqual);
	}

	static String base64Encode(
		byte[] buf, int off, int len, boolean withEqual)
	{
		StringBuilder sb = new StringBuilder();
		for (;;) {
			if (len < 3) {
				break;
			}
			int w = buf[off ++] & 0xFF;
			w = (w << 8) + (buf[off ++] & 0xFF);
			w = (w << 8) + (buf[off ++] & 0xFF);
			sb.append(BASE64.charAt(w >> 18));
			sb.append(BASE64.charAt((w >> 12) & 0x3F));
			sb.append(BASE64.charAt((w >> 6) & 0x3F));
			sb.append(BASE64.charAt(w & 0x3F));
			len -= 3;
		}
		switch (len) {
		case 0:
			break;
		case 1:
			int w1 = buf[off] & 0xFF;
			sb.append(BASE64.charAt(w1 >> 2));
			sb.append(BASE64.charAt((w1 << 4) & 0x3F));
			if (withEqual) {
				sb.append("==");
			}
			break;
		case 2:
			int w2 = ((buf[off] & 0xFF) << 8)
				+ (buf[off + 1] & 0xFF);
			sb.append(BASE64.charAt(w2 >> 10));
			sb.append(BASE64.charAt((w2 >> 4) & 0x3F));
			sb.append(BASE64.charAt((w2 << 2) & 0x3F));
			if (withEqual) {
				sb.append('=');
			}
			break;
		}
		return sb.toString();
	}

	static byte[] base64Decode(String str,
		boolean rejectBadChar, boolean expectEqual)
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int n = str.length();
		int numEq = 0;
		int acc = 0, k = 0;
		for (int i = 0; i < n; i ++) {
			int d = str.charAt(i);
			if (d >= 'A' && d <= 'Z') {
				d -= 'A';
			} else if (d >= 'a' && d <= 'z') {
				d -= ('a' - 26);
			} else if (d >= '0' && d <= '9') {
				d -= ('0' - 52);
			} else if (d == '+') {
				d = 62;
			} else if (d == '/') {
				d = 63;
			} else if (d == '=') {
				if (!expectEqual || numEq >= 2) {
					throw new MakwaException(
						"unexpected '=' sign");
				}
				numEq ++;
				d = -1;
			} else {
				if (rejectBadChar) {
					throw new MakwaException(
						"invalid Base64 string");
				}
				continue;
			}
			if (d < 0) {
				d = 0;
			} else {
				if (numEq != 0) {
					throw new IllegalArgumentException(
						"invalid Base64 termination");
				}
			}
			acc = (acc << 6) + d;
			if (++ k == 4) {
				baos.write(acc >>> 16);
				baos.write(acc >>> 8);
				baos.write(acc);
				acc = 0;
				k = 0;
			}
		}
		if (k != 0) {
			if (k == 1 || expectEqual) {
				throw new IllegalArgumentException(
					"truncated Base64 input");
			}
			switch (k) {
			case 2:
				baos.write(acc >>> 4);
				break;
			case 3:
				baos.write(acc >>> 10);
				baos.write(acc >>> 2);
				break;
			}
		}
		return baos.toByteArray();
	}

	private static int getWFMant(int wf)
	{
		while (wf > 3 && (wf & 1) == 0) {
			wf >>>= 1;
		}
		switch (wf) {
		case 2:
		case 3:
			return wf;
		default:
			throw new MakwaException("invalid work factor");
		}
	}

	private static int getWFLog(int wf)
	{
		int j = 0;
		while (wf > 3 && (wf & 1) == 0) {
			wf >>>= 1;
			j ++;
		}
		switch (wf) {
		case 2:
		case 3:
			return j;
		default:
			throw new MakwaException("invalid work factor");
		}
	}

	/**
	 * <p>A {@code Makwa.Output} instance represents a Makwa output,
	 * with its parameters. This class handles encoding to and
	 * decoding from the string representation described in the
	 * Makwa specification, section A.4.</p>
	 *
	 * <p>Use {@link Makwa#decodeOutput} to create instances of this
	 * class.</p>
	 */
	public class Output {

		private byte[] salt;
		private boolean preHash;
		private int postHashLength;
		private int workFactor;
		private byte[] tau;
		private BigInteger tauInt;

		Output(byte[] salt, boolean preHash, int postHashLength,
			int workFactor, byte[] tau)
		{
			this.salt = salt;
			this.preHash = preHash;
			this.postHashLength = postHashLength;
			this.workFactor = workFactor;
			this.tau = tau;
			if (postHashLength == 0) {
				tauInt = OS2IP(tau);
			} else if (postHashLength < 10) {
				throw new MakwaException("invalid parameters");
			} else {
				tauInt = null;
				if (tau.length != postHashLength) {
					throw new MakwaException(
						"invalid parameters");
				}
			}
		}

		Output(byte[] salt, boolean preHash, int postHashLength,
			int workFactor, BigInteger y)
		{
			this.salt = salt;
			this.preHash = preHash;
			this.postHashLength = postHashLength;
			this.workFactor = workFactor;
			tau = I2OSP(y);
			tauInt = y;
			if (postHashLength != 0) {
				throw new MakwaException("invalid parameters");
			}
		}

		Output(String str)
		{
			// Get modulus ID and verify it.
			int j = str.indexOf('_');
			if (j != 11) {
				throw new MakwaException(
					"invalid Makwa output string");
			}
			byte[] smod = base64Decode(
				str.substring(0, j), true, false);
			if (!Makwa.equals(smod, getModulusID())) {
				throw new MakwaException(
					"invalid Makwa output string");
			}
			str = str.substring(j + 1);

			// Get flags & work factor.
			j = str.indexOf('_');
			if (j != 4) {
				throw new MakwaException(
					"invalid Makwa output string");
			}
			char ht = str.charAt(0);
			switch (str.charAt(1)) {
			case '2':
				workFactor = 2;
				break;
			case '3':
				workFactor = 3;
				break;
			default:
				throw new MakwaException(
					"invalid Makwa output string");
			}
			int wlh = str.charAt(2) - '0';
			int wll = str.charAt(3) - '0';
			if (wlh < 0 || wlh > 9 || wll < 0 || wll > 9) {
				throw new MakwaException(
					"invalid Makwa output string");
			}
			int wl = 10 * wlh + wll;
			if (wl > 29) {
				throw new MakwaException(
					"unsupported work factor (too large)");
			}
			workFactor <<= wl;
			str = str.substring(j + 1);

			// Get salt.
			j = str.indexOf('_');
			if (j < 0) {
				throw new MakwaException(
					"invalid Makwa output string");
			}
			salt = base64Decode(
				str.substring(0, j), true, false);
			str = str.substring(j + 1);

			// Get output.
			tau = base64Decode(str, true, false);
			if (tau.length == 0) {
				throw new MakwaException(
					"invalid Makwa output string");
			}

			// Process flags.
			switch (ht) {
			case 'n':
				preHash = false;
				postHashLength = 0;
				break;
			case 'r':
				preHash = true;
				postHashLength = 0;
				break;
			case 's':
				preHash = false;
				postHashLength = tau.length;
				break;
			case 'b':
				preHash = true;
				postHashLength = tau.length;
				break;
			default:
				throw new MakwaException(
					"invalid Makwa output string");
			}
			if (postHashLength == 0) {
				tauInt = OS2IP(tau);
			} else if (postHashLength < 10) {
				throw new MakwaException(
					"invalid Makwa output string");
			} else {
				tauInt = null;
			}
		}

		/**
		 * Get the salt value.
		 *
		 * @return  the salt
		 */
		public byte[] getSalt()
		{
			return salt;
		}

		/**
		 * Get the pre-hashing flag.
		 *
		 * @return  {@code true} if pre-hashing was applied
		 */
		public boolean getPreHash()
		{
			return preHash;
		}

		/**
		 * Get the post-hashing length; 0 is returned if no
		 * post-hashing was applied. When post-hashing is applied,
		 * at least 10 bytes are produced.
		 *
		 * @return  the post-hashing length (in bytes), or 0.
		 */
		public int getPostHashLength()
		{
			return postHashLength;
		}

		/**
		 * Get the work factor. By definition, it is an
		 * "encodable" work factor (2 or 3 times a power of 2).
		 *
		 * @return  the work factor
		 */
		public int getWorkFactor()
		{
			return workFactor;
		}

		/**
		 * Get the binary output. This is either the encoded
		 * primary output, if no post-hashing was applied, or the
		 * post-hash output.
		 *
		 * @return  the binary output
		 */
		public byte[] getTau()
		{
			return tau;
		}

		/**
		 * Get the primary output as a big integer. If post-hashing
		 * was applied, then this method returns {@code null}. If
		 * an integer is returned, then it has been verified to
		 * be in the correct range (1 to n-1, where n is the modulus).
		 *
		 * @return  the primary output, or {@code null}
		 */
		public BigInteger getTauInt()
		{
			return tauInt;
		}

		/**
		 * Re-encode this Makwa output as a string using the
		 * specified format.
		 *
		 * @see Object
		 */
		public String toString()
		{
			StringBuilder sb = new StringBuilder();
			sb.append(base64Encode(getModulusID(), false));
			sb.append('_');
			if (preHash) {
				if (postHashLength > 0) {
					sb.append('b');
				} else {
					sb.append('r');
				}
			} else {
				if (postHashLength > 0) {
					sb.append('s');
				} else {
					sb.append('n');
				}
			}
			sb.append((char)('0' + getWFMant(workFactor)));
			int wl = getWFLog(workFactor);
			sb.append((char)('0' + (wl / 10)));
			sb.append((char)('0' + (wl % 10)));
			sb.append('_');
			sb.append(base64Encode(salt, false));
			sb.append('_');
			sb.append(base64Encode(tau, false));
			return sb.toString();
		}
	}
}
