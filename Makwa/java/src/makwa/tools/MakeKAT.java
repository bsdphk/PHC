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

package makwa.tools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import makwa.Makwa;
import makwa.MakwaException;
import makwa.MakwaPrivateKey;

/**
 * This command-line tool generates Known Answer Test values for Makwa.
 * The vector values are printed out, and an aggregate hash is computed.
 *
 * @version   $Revision$
 * @author    Thomas Pornin
 */

public class MakeKAT {

	private static final byte[] PUB2048 = {
		(byte)0x55, (byte)0x41, (byte)0x4d, (byte)0x30,
		(byte)0x01, (byte)0x00, (byte)0xc2, (byte)0x2c,
		(byte)0x40, (byte)0xbb, (byte)0xd0, (byte)0x56,
		(byte)0xbb, (byte)0x21, (byte)0x3a, (byte)0xad,
		(byte)0x7c, (byte)0x83, (byte)0x05, (byte)0x19,
		(byte)0x10, (byte)0x1a, (byte)0xb9, (byte)0x26,
		(byte)0xae, (byte)0x18, (byte)0xe3, (byte)0xe9,
		(byte)0xfc, (byte)0x96, (byte)0x99, (byte)0xc8,
		(byte)0x06, (byte)0xe0, (byte)0xae, (byte)0x5c,
		(byte)0x25, (byte)0x94, (byte)0x14, (byte)0xa0,
		(byte)0x1a, (byte)0xc1, (byte)0xd5, (byte)0x2e,
		(byte)0x87, (byte)0x3e, (byte)0xc0, (byte)0x80,
		(byte)0x46, (byte)0xa6, (byte)0x8e, (byte)0x34,
		(byte)0x4c, (byte)0x8d, (byte)0x74, (byte)0xa5,
		(byte)0x08, (byte)0x95, (byte)0x28, (byte)0x42,
		(byte)0xef, (byte)0x0f, (byte)0x03, (byte)0xf7,
		(byte)0x1a, (byte)0x6e, (byte)0xdc, (byte)0x07,
		(byte)0x7f, (byte)0xaa, (byte)0x14, (byte)0x89,
		(byte)0x9a, (byte)0x79, (byte)0xf8, (byte)0x3c,
		(byte)0x3a, (byte)0xe1, (byte)0x36, (byte)0xf7,
		(byte)0x74, (byte)0xfa, (byte)0x6e, (byte)0xb8,
		(byte)0x8f, (byte)0x1d, (byte)0x1a, (byte)0xea,
		(byte)0x5e, (byte)0xa0, (byte)0x2f, (byte)0xc0,
		(byte)0xcc, (byte)0xaf, (byte)0x96, (byte)0xe2,
		(byte)0xce, (byte)0x86, (byte)0xf3, (byte)0x49,
		(byte)0x0f, (byte)0x49, (byte)0x93, (byte)0xb4,
		(byte)0xb5, (byte)0x66, (byte)0xc0, (byte)0x07,
		(byte)0x96, (byte)0x41, (byte)0x47, (byte)0x2d,
		(byte)0xef, (byte)0xc1, (byte)0x4b, (byte)0xec,
		(byte)0xcf, (byte)0x48, (byte)0x98, (byte)0x4a,
		(byte)0x79, (byte)0x46, (byte)0xf1, (byte)0x44,
		(byte)0x1e, (byte)0xa1, (byte)0x44, (byte)0xea,
		(byte)0x4c, (byte)0x80, (byte)0x2a, (byte)0x45,
		(byte)0x75, (byte)0x50, (byte)0xba, (byte)0x3d,
		(byte)0xf0, (byte)0xf1, (byte)0x4c, (byte)0x09,
		(byte)0x0a, (byte)0x75, (byte)0xfe, (byte)0x9e,
		(byte)0x6a, (byte)0x77, (byte)0xcf, (byte)0x0b,
		(byte)0xe9, (byte)0x8b, (byte)0x71, (byte)0xd5,
		(byte)0x62, (byte)0x51, (byte)0xa8, (byte)0x69,
		(byte)0x43, (byte)0xe7, (byte)0x19, (byte)0xd2,
		(byte)0x78, (byte)0x65, (byte)0xa4, (byte)0x89,
		(byte)0x56, (byte)0x6c, (byte)0x1d, (byte)0xc5,
		(byte)0x7f, (byte)0xcd, (byte)0xef, (byte)0xac,
		(byte)0xa6, (byte)0xab, (byte)0x04, (byte)0x3f,
		(byte)0x8e, (byte)0x13, (byte)0xf6, (byte)0xc0,
		(byte)0xbe, (byte)0x7b, (byte)0x39, (byte)0xc9,
		(byte)0x2d, (byte)0xa8, (byte)0x6e, (byte)0x1d,
		(byte)0x87, (byte)0x47, (byte)0x7a, (byte)0x18,
		(byte)0x9e, (byte)0x73, (byte)0xce, (byte)0x8e,
		(byte)0x31, (byte)0x1d, (byte)0x3d, (byte)0x51,
		(byte)0x36, (byte)0x1f, (byte)0x8b, (byte)0x00,
		(byte)0x24, (byte)0x9f, (byte)0xb3, (byte)0xd8,
		(byte)0x43, (byte)0x56, (byte)0x07, (byte)0xb1,
		(byte)0x4a, (byte)0x1e, (byte)0x70, (byte)0x17,
		(byte)0x0f, (byte)0x9a, (byte)0xf3, (byte)0x67,
		(byte)0x84, (byte)0x11, (byte)0x0a, (byte)0x3f,
		(byte)0x2e, (byte)0x67, (byte)0x42, (byte)0x8f,
		(byte)0xc1, (byte)0x8f, (byte)0xb0, (byte)0x13,
		(byte)0xb3, (byte)0x0f, (byte)0xe6, (byte)0x78,
		(byte)0x2a, (byte)0xec, (byte)0xb4, (byte)0x42,
		(byte)0x8d, (byte)0x7c, (byte)0x8e, (byte)0x35,
		(byte)0x4a, (byte)0x0f, (byte)0xbd, (byte)0x06,
		(byte)0x1b, (byte)0x01, (byte)0x91, (byte)0x7c,
		(byte)0x72, (byte)0x7a, (byte)0xbe, (byte)0xe0,
		(byte)0xfe, (byte)0x3f, (byte)0xd3, (byte)0xce,
		(byte)0xf7, (byte)0x61
	};

	private static final byte[] PRIV2048 = {
		(byte)0x55, (byte)0x41, (byte)0x4d, (byte)0x31,
		(byte)0x00, (byte)0x80, (byte)0xea, (byte)0x43,
		(byte)0xd7, (byte)0x9d, (byte)0xf0, (byte)0xb8,
		(byte)0x74, (byte)0x14, (byte)0x0a, (byte)0x55,
		(byte)0xec, (byte)0xd1, (byte)0x44, (byte)0x73,
		(byte)0x2e, (byte)0xaf, (byte)0x49, (byte)0xd9,
		(byte)0xc8, (byte)0xf0, (byte)0xe4, (byte)0x37,
		(byte)0x6f, (byte)0x5d, (byte)0x72, (byte)0x97,
		(byte)0x2a, (byte)0x14, (byte)0x66, (byte)0x79,
		(byte)0xe3, (byte)0x82, (byte)0x44, (byte)0xf5,
		(byte)0xa9, (byte)0x6e, (byte)0xf5, (byte)0xce,
		(byte)0x92, (byte)0x8a, (byte)0x54, (byte)0x25,
		(byte)0x12, (byte)0x40, (byte)0x47, (byte)0x5f,
		(byte)0xd1, (byte)0xdd, (byte)0x96, (byte)0x8b,
		(byte)0x9a, (byte)0x77, (byte)0xad, (byte)0xd1,
		(byte)0x65, (byte)0x50, (byte)0x56, (byte)0x4c,
		(byte)0x1d, (byte)0xd2, (byte)0x42, (byte)0x40,
		(byte)0x08, (byte)0xea, (byte)0x83, (byte)0xc2,
		(byte)0x59, (byte)0xd5, (byte)0x3b, (byte)0x88,
		(byte)0x61, (byte)0xc5, (byte)0xe9, (byte)0x4f,
		(byte)0x22, (byte)0x8f, (byte)0x03, (byte)0xc4,
		(byte)0x98, (byte)0xdd, (byte)0x3c, (byte)0x8c,
		(byte)0x69, (byte)0x49, (byte)0xe3, (byte)0x66,
		(byte)0x02, (byte)0xfe, (byte)0x74, (byte)0x6d,
		(byte)0x64, (byte)0xd5, (byte)0x14, (byte)0x89,
		(byte)0xc7, (byte)0x6c, (byte)0x74, (byte)0xdb,
		(byte)0xc2, (byte)0x44, (byte)0x7e, (byte)0x22,
		(byte)0x2e, (byte)0xcf, (byte)0x28, (byte)0xfa,
		(byte)0x9b, (byte)0xd4, (byte)0x4e, (byte)0x81,
		(byte)0x41, (byte)0x07, (byte)0x55, (byte)0x87,
		(byte)0x9e, (byte)0x71, (byte)0xbd, (byte)0xf8,
		(byte)0xfb, (byte)0x4a, (byte)0x61, (byte)0xd8,
		(byte)0xad, (byte)0x3d, (byte)0xf4, (byte)0x4f,
		(byte)0xfc, (byte)0x9b, (byte)0x00, (byte)0x80,
		(byte)0xd4, (byte)0x30, (byte)0x28, (byte)0xee,
		(byte)0x37, (byte)0x4f, (byte)0xeb, (byte)0xb9,
		(byte)0x3b, (byte)0x5d, (byte)0xf8, (byte)0xdc,
		(byte)0x1c, (byte)0x68, (byte)0x37, (byte)0x13,
		(byte)0xab, (byte)0x05, (byte)0x10, (byte)0xaf,
		(byte)0x7e, (byte)0xeb, (byte)0xe6, (byte)0x3d,
		(byte)0x33, (byte)0xf9, (byte)0x0a, (byte)0xf7,
		(byte)0x63, (byte)0xfa, (byte)0x22, (byte)0x64,
		(byte)0xb6, (byte)0x8b, (byte)0x09, (byte)0x21,
		(byte)0x94, (byte)0x90, (byte)0xa5, (byte)0xa5,
		(byte)0x64, (byte)0x4d, (byte)0x63, (byte)0x56,
		(byte)0x85, (byte)0x9c, (byte)0x27, (byte)0xcd,
		(byte)0xf9, (byte)0x76, (byte)0x71, (byte)0x12,
		(byte)0x2e, (byte)0x4d, (byte)0x9a, (byte)0x13,
		(byte)0xd9, (byte)0x16, (byte)0x09, (byte)0x60,
		(byte)0x9c, (byte)0x46, (byte)0x90, (byte)0x14,
		(byte)0xda, (byte)0xe3, (byte)0x0f, (byte)0x9a,
		(byte)0xe6, (byte)0xbc, (byte)0x93, (byte)0x78,
		(byte)0xe7, (byte)0x97, (byte)0x47, (byte)0x60,
		(byte)0x1e, (byte)0xee, (byte)0xa8, (byte)0x18,
		(byte)0x46, (byte)0x98, (byte)0x42, (byte)0x72,
		(byte)0x08, (byte)0x9c, (byte)0x08, (byte)0x53,
		(byte)0x49, (byte)0x7f, (byte)0xc5, (byte)0x3a,
		(byte)0x51, (byte)0xd4, (byte)0x5d, (byte)0x37,
		(byte)0xf0, (byte)0xcb, (byte)0x4e, (byte)0x67,
		(byte)0xd8, (byte)0xb9, (byte)0x59, (byte)0x21,
		(byte)0xb7, (byte)0xd2, (byte)0x93, (byte)0xd7,
		(byte)0x55, (byte)0xb4, (byte)0x9d, (byte)0xda,
		(byte)0x55, (byte)0xb8, (byte)0x15, (byte)0x29,
		(byte)0xa7, (byte)0x06, (byte)0xcd, (byte)0x67,
		(byte)0xee, (byte)0x3b, (byte)0xfe, (byte)0xfe,
		(byte)0xc4, (byte)0xf3, (byte)0xf5, (byte)0xb3
	};

	/*
	 * 16 salt values which exercise all byte values from 0 to
	 * 255. These values were produced from a random permutation
	 * (from /dev/uradnom) of bytes 0x00 to 0xff.
	 */
	private static final byte[][] SALTS = {
		{ /* 0 */
			(byte)0xb8, (byte)0x2c, (byte)0xb4, (byte)0x2e,
			(byte)0x3a, (byte)0x2d, (byte)0xfc, (byte)0x2a,
			(byte)0xd6, (byte)0x0b, (byte)0x8b, (byte)0x76,
			(byte)0xc6, (byte)0x66, (byte)0xb0, (byte)0x15
		},
		{ /* 1 */
			(byte)0xa8, (byte)0x67, (byte)0xf0, (byte)0x36,
			(byte)0xcc, (byte)0x97, (byte)0x43, (byte)0x41,
			(byte)0x5a, (byte)0x7c, (byte)0xf8, (byte)0xe7,
			(byte)0x6f, (byte)0x3d, (byte)0x79, (byte)0xc3
		},
		{ /* 2 */
			(byte)0x07, (byte)0x96, (byte)0x09, (byte)0x03,
			(byte)0x6d, (byte)0xd1, (byte)0x89, (byte)0x4c,
			(byte)0xe3, (byte)0x7d, (byte)0x08, (byte)0xab,
			(byte)0x20, (byte)0x21, (byte)0xa3, (byte)0x02
		},
		{ /* 3 */
			(byte)0x1a, (byte)0xdb, (byte)0xc1, (byte)0xe6,
			(byte)0xa9, (byte)0xdd, (byte)0x48, (byte)0x1f,
			(byte)0xff, (byte)0x00, (byte)0xeb, (byte)0x93,
			(byte)0xb2, (byte)0x8e, (byte)0x9a, (byte)0xce
		},
		{ /* 4 */
			(byte)0xd8, (byte)0x8f, (byte)0x1d, (byte)0x9b,
			(byte)0x71, (byte)0xd0, (byte)0xa1, (byte)0x59,
			(byte)0xf1, (byte)0x1b, (byte)0x28, (byte)0x84,
			(byte)0x78, (byte)0x18, (byte)0x29, (byte)0x16
		},
		{ /* 5 */
			(byte)0x1c, (byte)0x37, (byte)0x22, (byte)0x64,
			(byte)0x42, (byte)0x19, (byte)0xb5, (byte)0xcd,
			(byte)0x55, (byte)0xf3, (byte)0x68, (byte)0xcf,
			(byte)0xcb, (byte)0xe5, (byte)0x4e, (byte)0xd7
		},
		{ /* 6 */
			(byte)0x82, (byte)0xef, (byte)0x58, (byte)0x8d,
			(byte)0xd5, (byte)0xc5, (byte)0x52, (byte)0xdf,
			(byte)0xa2, (byte)0xf6, (byte)0x46, (byte)0x99,
			(byte)0x87, (byte)0x91, (byte)0xa5, (byte)0x75
		},
		{ /* 7 */
			(byte)0x4b, (byte)0x9f, (byte)0x85, (byte)0x74,
			(byte)0x2f, (byte)0x0c, (byte)0xfb, (byte)0xda,
			(byte)0xde, (byte)0x12, (byte)0xb7, (byte)0x3e,
			(byte)0x54, (byte)0xb9, (byte)0x95, (byte)0x10
		},
		{ /* 8 */
			(byte)0xaf, (byte)0xa6, (byte)0xa0, (byte)0x92,
			(byte)0xf2, (byte)0x35, (byte)0x4a, (byte)0x8a,
			(byte)0xaa, (byte)0x0e, (byte)0x80, (byte)0x23,
			(byte)0x56, (byte)0xe4, (byte)0x7e, (byte)0x01
		},
		{ /* 9 */
			(byte)0x60, (byte)0xf4, (byte)0x8c, (byte)0xdc,
			(byte)0x69, (byte)0x3f, (byte)0x2b, (byte)0x7b,
			(byte)0xc0, (byte)0x6b, (byte)0xc9, (byte)0x13,
			(byte)0x53, (byte)0x86, (byte)0x30, (byte)0xbc
		},
		{ /* 10 */
			(byte)0x06, (byte)0xbe, (byte)0xfd, (byte)0x62,
			(byte)0xea, (byte)0xc8, (byte)0xe0, (byte)0x5d,
			(byte)0x4d, (byte)0x65, (byte)0x39, (byte)0xa4,
			(byte)0xe9, (byte)0xf5, (byte)0xba, (byte)0xfa
		},
		{ /* 11 */
			(byte)0x73, (byte)0x9c, (byte)0x40, (byte)0x51,
			(byte)0xf7, (byte)0x04, (byte)0x6c, (byte)0x33,
			(byte)0xad, (byte)0x11, (byte)0x1e, (byte)0x7f,
			(byte)0xed, (byte)0x3c, (byte)0x9d, (byte)0x34
		},
		{ /* 12 */
			(byte)0x31, (byte)0x24, (byte)0x44, (byte)0xb6,
			(byte)0x83, (byte)0x88, (byte)0x9e, (byte)0x94,
			(byte)0x5e, (byte)0xd4, (byte)0x47, (byte)0x26,
			(byte)0x49, (byte)0xe1, (byte)0x6a, (byte)0x0d
		},
		{ /* 13 */
			(byte)0xbf, (byte)0xfe, (byte)0xbb, (byte)0x98,
			(byte)0x5b, (byte)0xc4, (byte)0xc7, (byte)0x5f,
			(byte)0x77, (byte)0xa7, (byte)0x81, (byte)0xd3,
			(byte)0x0f, (byte)0xe8, (byte)0x7a, (byte)0xee
		},
		{ /* 14 */
			(byte)0x63, (byte)0xf9, (byte)0xc2, (byte)0x27,
			(byte)0xd2, (byte)0x5c, (byte)0xae, (byte)0x3b,
			(byte)0xd9, (byte)0x45, (byte)0x4f, (byte)0x61,
			(byte)0x05, (byte)0x0a, (byte)0x90, (byte)0xbd
		},
		{ /* 15 */
			(byte)0xe2, (byte)0x38, (byte)0x17, (byte)0x25,
			(byte)0x14, (byte)0xca, (byte)0xb3, (byte)0x57,
			(byte)0xb1, (byte)0x50, (byte)0xec, (byte)0x32,
			(byte)0x72, (byte)0x6e, (byte)0x70, (byte)0xac
		}
	};

	private static final int WF_SMALL = 384;
	private static final int WF_LARGE = 4096;

	public static void main(String[] args)
		throws IOException
	{
		new MakeKAT().process();
	}

	private MessageDigest sha256;

	private void process()
		throws IOException
	{
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException nsae) {
			throw new MakwaException("no native SHA-256");
		}

		BigInteger mod = MakwaPrivateKey.decodePublic(PUB2048);
		MakwaPrivateKey pkey = new MakwaPrivateKey(PRIV2048);
		check(mod.equals(pkey.getModulus()));
		Makwa mpub = new Makwa(mod, Makwa.SHA256, false, 0, 1024);
		Makwa mpriv = new Makwa(pkey, Makwa.SHA256, false, 0, 1024);

		/*
		 * Some KDF test vectors.
		 */
		for (int i = 0; i < 200; i ++) {
			byte[] input = new byte[i];
			for (int j = 0; j < i; j ++) {
				input[j] = (byte)(7 * i + 83 * j);
			}
			printKDF("KDF/SHA-256", Makwa.SHA256, input, 100);
			printKDF("KDF/SHA-512", Makwa.SHA512, input, 100);
		}

		/*
		 * The detailed test vector from the specification.
		 */
		byte[] pi;
		try {
			String pwd = "Gego beshwaji'aaken awe makwa;"
				+ " onzaam naniizaanizi.";
			pi = pwd.getBytes("UTF-8");
		} catch (Exception e) {
			throw new Error(e);
		}
		byte[] salt = new byte[] {
			(byte)0xC7, (byte)0x27, (byte)0x03, (byte)0xC2,
			(byte)0x2A, (byte)0x96, (byte)0xD9, (byte)0x99,
			(byte)0x2F, (byte)0x3D, (byte)0xEA, (byte)0x87,
			(byte)0x64, (byte)0x97, (byte)0xE3, (byte)0x92
		};
		byte[] ref = new byte[] {
			(byte)0xC9, (byte)0xCE, (byte)0xA0, (byte)0xE6,
			(byte)0xEF, (byte)0x09, (byte)0x39, (byte)0x3A,
			(byte)0xB1, (byte)0x71, (byte)0x0A, (byte)0x08
		};
		check(equals(ref, mpub.doHash(pi, salt, false, 12, 4096)));
		String detailed = mpub.encodeOutput(salt, false, 12, 4096, ref);
		System.out.println("2048-bit modulus, SHA-256");
		println("input", pi);
		println("salt", salt);
		System.out.println("pre-hashing: false");
		System.out.println("post-hashing: 12");
		println("bin4096", ref);
		System.out.println("str4096: " + detailed);
		System.out.println();

		sha256.update(ref);
		sha256.update(detailed.getBytes("UTF-8"));

		/*
		 * A lot of test vectors of various sizes and parameters.
		 */
		printKAT("2048-bit modulus, SHA-256", mpub, mpriv);

		mpub = new Makwa(mod, Makwa.SHA512, false, 0, 1024);
		mpriv = new Makwa(pkey, Makwa.SHA512, false, 0, 1024);
		printKAT("2048-bit modulus, SHA-512", mpub, mpriv);

		println("KAT digest", sha256.digest());
	}

	private static void check(boolean v)
	{
		if (!v) {
			throw new MakwaException("self-test failed");
		}
	}

	private void printKDF(String banner,
		int hashFunction, byte[] input, int outLen)
	{
		byte[] output = new byte[outLen];
		Makwa.doKDF(hashFunction, input, output);
		System.out.println(banner);
		println("input", input);
		println("output", output);
		System.out.println();
		sha256.update(output);
	}

	private void printKAT(String banner,
		Makwa mpub, Makwa mpriv)
		throws IOException
	{
		/*
		 * A 150-byte input, which exercises the "input length"
		 * as an unsigned byte.
		 */
		byte[] input = new byte[150];
		for (int i = 0; i < input.length; i ++) {
			input[i] = (byte)(17 + 73 * i);
		}
		printKAT(banner, mpub, mpriv, input);

		/*
		 * Some 13-byte inputs, rotating over the 256 possible bytes.
		 * One of them has an embedded 0.
		 */
		input = new byte[13];
		for (int i = 0; i < 22; i ++) {
			for (int j = 0; j < 13; j ++) {
				input[j] = (byte)(13 * i + j + 8);
			}
			printKAT(banner, mpub, mpriv, input);
		}
	}

	private void printKAT(String banner,
		Makwa mpub, Makwa mpriv, byte[] input)
		throws IOException
	{
		for (int saltNum = 0; saltNum < SALTS.length; saltNum ++) {
			byte[] salt = SALTS[saltNum];
			printKAT(banner, mpub, mpriv, input, salt,
				10 + saltNum);
		}
	}

	private void printKAT(String banner,
		Makwa mpub, Makwa mpriv, byte[] input, byte[] salt, int phLen)
		throws IOException
	{
		printKAT(banner, mpub, mpriv, input, salt, false, 0);
		printKAT(banner, mpub, mpriv, input, salt, false, phLen);
		printKAT(banner, mpub, mpriv, input, salt, true, 0);
		printKAT(banner, mpub, mpriv, input, salt, true, phLen);
	}

	private void printKAT(String banner,
		Makwa mpub, Makwa mpriv, byte[] input, byte[] salt,
		boolean preHash, int postHashLength)
		throws IOException
	{
		byte[] outSmall = mpub.doHash(input, salt,
			preHash, postHashLength, WF_SMALL);
		check(equals(outSmall, mpriv.doHash(input, salt,
			preHash, postHashLength, WF_SMALL)));
		String outSmallString = mpriv.doHashToString(input, salt,
			preHash, postHashLength, WF_SMALL);
		byte[] outLarge = mpub.doHash(input, salt,
			preHash, postHashLength, WF_LARGE);
		check(equals(outLarge, mpriv.doHash(input, salt,
			preHash, postHashLength, WF_LARGE)));
		String outLargeString = mpriv.doHashToString(input, salt,
			preHash, postHashLength, WF_LARGE);
		System.out.println(banner);
		println("input", input);
		println("salt", salt);
		System.out.println("pre-hashing: " + preHash);
		if (postHashLength == 0) {
			System.out.println("post-hashing: false");
		} else {
			System.out.println("post-hashing: "
				+ postHashLength);
		}
		println("bin" + WF_SMALL, outSmall);
		println("bin" + WF_LARGE, outLarge);
		System.out.println("str" + WF_SMALL + ": " + outSmallString);
		System.out.println("str" + WF_LARGE + ": " + outLargeString);
		System.out.println();

		sha256.update(outSmall);
		sha256.update(outLarge);
		sha256.update(outSmallString.getBytes("UTF-8"));
		sha256.update(outLargeString.getBytes("UTF-8"));

		if (!preHash && postHashLength == 0) {
			byte[] upi1 = mpriv.unescrow(outSmall, salt, WF_SMALL);
			check(equals(upi1, input));
			byte[] upi2 = mpriv.unescrow(outLarge, salt, WF_LARGE);
			check(equals(upi2, input));
		}
	}

	private static void println(String name, byte[] value)
	{
		System.out.print(name + ": ");
		for (int i = 0; i < value.length; i ++) {
			System.out.printf("%02x", value[i] & 0xFF);
		}
		System.out.println();
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

	/* obsolete
	private static byte[] hexToBin(String s)
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int n = s.length();
		int acc = 0;
		boolean z = false;
		for (int i = 0; i < n; i ++) {
			int c = s.charAt(i);
			int d;
			if (c >= '0' && c <= '9') {
				d = c - '0';
			} else if (c >= 'A' && c <= 'F') {
				d = c - ('A' - 10);
			} else if (c >= 'a' && c <= 'f') {
				d = c - ('a' - 10);
			} else {
				continue;
			}
			if (z) {
				baos.write((acc << 4) + d);
			} else {
				acc = d;
			}
			z = !z;
		}
		if (z) {
			throw new MakwaException(
				"invalid hex string (partial byte)");
		}
		return baos.toByteArray();
	}
	*/
}
