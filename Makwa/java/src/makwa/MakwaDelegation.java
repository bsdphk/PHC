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

/**
 * <p>A {@code MakwaDelegation} instance contains the parameters needed
 * to perform work delegation to an external system (the "delegation
 * server"). Such a set of parameters is specific to a given modulus
 * and work factor. Under normal conditions, it is expected that sets
 * of parameters are created once, then saved in encoded format
 * (as returned by {@link #export}), and decoded again at application
 * start-up.</p>
 *
 * <p>A new set of parameters (for a newly created modulus, or an hitherto
 * unused work factor) can be obtained with {@link #generate}. The modulus
 * is provided as either an encoded modulus, or an encoded Makwa private
 * key. Since generating a set of parameters has a cost similar to computing
 * Makwa 300 times, it is recommended to use a Makwa private key, which
 * enables the "fast path".</p>
 *
 * <p>Instances are immutable and thread-safe.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class MakwaDelegation {

	private static final int DEFAULT_NUM_MASKS = 300;

	private BigInteger modulus;
	private int workFactor;
	private BigInteger[] alpha;
	private BigInteger[] beta;

	private MakwaDelegation(BigInteger modulus, int workFactor,
		BigInteger[] alpha, BigInteger[] beta)
	{
		init(modulus, workFactor, alpha, beta);
	}

	/**
	 * Create an instance by decoding a set of delegation parameters.
	 *
	 * @param params   the encoded parameters
	 * @throws MakwaException  on decoding error
	 */
	public MakwaDelegation(byte[] params)
	{
		try {
			InputStream in = new ByteArrayInputStream(params);
			int magic = MakwaIO.read32(in);
			switch (magic) {
			case MakwaIO.MAGIC_DELEG_PARAM:
				BigInteger mod = MakwaIO.readMPI(in);
				int wf = MakwaIO.read32(in);
				int num = MakwaIO.read16(in);
				BigInteger[] alpha = new BigInteger[num];
				BigInteger[] beta = new BigInteger[num];
				for (int i = 0; i < num; i ++) {
					alpha[i] = MakwaIO.readMPI(in);
					beta[i] = MakwaIO.readMPI(in);
				}
				checkEOF(in);
				init(mod, wf, alpha, beta);
				break;
			default:
				throw new MakwaException("unknown Makwa"
					+ " delegation parameter type");
			}
		} catch (IOException ioe) {
			throw new MakwaException("invalid Makwa"
				+ " delegation parameter (truncated)");
		}
	}

	private static void checkEOF(InputStream in)
		throws IOException
	{
		if (in.read() >= 0) {
			throw new MakwaException("invalid Makwa"
				+ " delegation parameter (trailing garbage)");
		}
	}

	private void init(BigInteger modulus, int workFactor,
		BigInteger[] alpha, BigInteger[] beta)
	{
		if (modulus.signum() <= 0 || modulus.bitLength() < 1273
			|| (modulus.intValue() & 3) != 1)
		{
			throw new MakwaException("invalid modulus");
		}
		if (workFactor < 0) {
			throw new MakwaException("invalid work factor");
		}
		int n = alpha.length;
		if (n > 65535) {
			throw new MakwaException("too many mask pairs");
		}
		if (n != beta.length) {
			throw new MakwaException("invalid mask pairs");
		}
		for (int i = 0; i < n; i ++) {
			BigInteger a = alpha[i];
			BigInteger b = beta[i];
			if (a.signum() <= 0 || a.compareTo(modulus) >= 0) {
				throw new MakwaException("invalid mask value");
			}
			if (b.signum() <= 0 || b.compareTo(modulus) >= 0) {
				throw new MakwaException("invalid mask value");
			}
		}
		this.modulus = modulus;
		this.workFactor = workFactor;
		this.alpha = alpha;
		this.beta = beta;
	}

	/**
	 * Encode this set of parameters.
	 *
	 * @return  the encoded parameters
	 */
	public byte[] export()
	{
		try {
			ByteArrayOutputStream baos =
				new ByteArrayOutputStream();
			MakwaIO.write32(baos, MakwaIO.MAGIC_DELEG_PARAM);
			MakwaIO.writeMPI(baos, modulus);
			MakwaIO.write32(baos, workFactor);
			int num = alpha.length;
			MakwaIO.write16(baos, num);
			for (int i = 0; i < num; i ++) {
				MakwaIO.writeMPI(baos, alpha[i]);
				MakwaIO.writeMPI(baos, beta[i]);
			}
			return baos.toByteArray();
		} catch (IOException ioe) {
			// This cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Get the modulus used by this set of delegation parameters.
	 *
	 * @return  the modulus
	 */
	public BigInteger getModulus()
	{
		return modulus;
	}

	/**
	 * Get the work factor for which this set of parameters was created.
	 *
	 * @return  the work factor
	 */
	public int getWorkFactor()
	{
		return workFactor;
	}

	/**
	 * Generate a new set of delegation parameters. The {@code mparam}
	 * argument must contains an encoded Makwa modulus, or an
	 * encoded Makwa private key (the latter is recommended; otherwise,
	 * the generation can be computationally expensive).
	 *
	 * @param mparam       the Makwa modulus or private key
	 * @param workFactor   the work factor
	 * @throws MakwaException  on error
	 */
	public static MakwaDelegation generate(byte[] mparam, int workFactor)
	{
		try {
			Makwa mkw = new Makwa(mparam, 0, false, 0, 0);
			BigInteger mod = mkw.getModulus();
			int num = DEFAULT_NUM_MASKS;
			BigInteger[] alpha = new BigInteger[num];
			BigInteger[] beta = new BigInteger[num];
			for (int i = 0; i < num; i ++) {
				BigInteger r =
					MakwaPrivateKey.makeRandNonZero(mod);
				alpha[i] = r.multiply(r).mod(mod);
				beta[i] = mkw.multiSquare(
					alpha[i], workFactor).modInverse(mod);
			}
			return new MakwaDelegation(
				mod, workFactor, alpha, beta);
		} catch (ArithmeticException ae) {
			// This never happens if the modulus has the
			// correct format.
			throw new MakwaException(ae);
		}
	}

	BigInteger[] createMaskPair()
	{
		int num = alpha.length;
		byte[] bits = new byte[(num + 7) >>> 3];
		MakwaPrivateKey.prng(bits);
		BigInteger v1 = BigInteger.ONE;
		BigInteger v2 = BigInteger.ONE;
		for (int i = 0; i < num; i ++) {
			if ((bits[i >>> 3] & (1 << (i & 7))) != 0) {
				v1 = v1.multiply(alpha[i]).mod(modulus);
				v2 = v2.multiply(beta[i]).mod(modulus);
			}
		}
		return new BigInteger[] { v1, v2 };
	}
}
