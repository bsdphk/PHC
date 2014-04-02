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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import makwa.Makwa;
import makwa.MakwaDelegation;
import makwa.MakwaException;
import makwa.MakwaPrivateKey;

/**
 * This command-line tool runs self-tests.
 *
 * @version   $Revision$
 * @author    Thomas Pornin
 */

public class SelfTest {

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
	 * This is the public modulus used by the C reference
	 * implementation for the PHS() function (meant for
	 * formal compliance to the Password Hash Competition
	 * submission API).
	 */
	private static byte[] PHC_PUB2048 = {
		(byte)0x55, (byte)0x41, (byte)0x4d, (byte)0x30,
		(byte)0x01, (byte)0x00, (byte)0xc0, (byte)0x84,
		(byte)0x7e, (byte)0xa3, (byte)0x72, (byte)0xa4,
		(byte)0xd0, (byte)0xdb, (byte)0xa1, (byte)0xa3,
		(byte)0x20, (byte)0x48, (byte)0x89, (byte)0x4d,
		(byte)0xc7, (byte)0x99, (byte)0x97, (byte)0xa1,
		(byte)0x0b, (byte)0x84, (byte)0x2a, (byte)0x9d,
		(byte)0xb1, (byte)0x5f, (byte)0xc5, (byte)0x61,
		(byte)0x4b, (byte)0xe5, (byte)0xa5, (byte)0x73,
		(byte)0xba, (byte)0xcc, (byte)0x72, (byte)0xa9,
		(byte)0x88, (byte)0x0a, (byte)0x57, (byte)0x98,
		(byte)0xa3, (byte)0x87, (byte)0x53, (byte)0x9b,
		(byte)0x7a, (byte)0x4c, (byte)0x1c, (byte)0x71,
		(byte)0xb6, (byte)0xb1, (byte)0x3a, (byte)0x84,
		(byte)0xdb, (byte)0xad, (byte)0xaf, (byte)0x9b,
		(byte)0x03, (byte)0xf7, (byte)0x6f, (byte)0x32,
		(byte)0x70, (byte)0x84, (byte)0x49, (byte)0xc4,
		(byte)0xfd, (byte)0x27, (byte)0xd2, (byte)0xc4,
		(byte)0xaf, (byte)0xc9, (byte)0xdc, (byte)0x46,
		(byte)0xc4, (byte)0xa6, (byte)0xbe, (byte)0xc5,
		(byte)0x5e, (byte)0x3a, (byte)0x3d, (byte)0xb1,
		(byte)0xa9, (byte)0xa2, (byte)0x56, (byte)0xaf,
		(byte)0x05, (byte)0x39, (byte)0xed, (byte)0x2a,
		(byte)0xb4, (byte)0x48, (byte)0xb8, (byte)0x53,
		(byte)0xb0, (byte)0xc1, (byte)0xaf, (byte)0x20,
		(byte)0x7b, (byte)0x6e, (byte)0xa2, (byte)0x94,
		(byte)0x06, (byte)0x34, (byte)0x91, (byte)0xfb,
		(byte)0x5e, (byte)0xb2, (byte)0xdc, (byte)0x95,
		(byte)0x0e, (byte)0x8e, (byte)0x1e, (byte)0x87,
		(byte)0x19, (byte)0xc4, (byte)0xe5, (byte)0x3c,
		(byte)0x06, (byte)0xdd, (byte)0x3e, (byte)0x7a,
		(byte)0x36, (byte)0x4b, (byte)0x44, (byte)0x65,
		(byte)0x26, (byte)0x81, (byte)0x7d, (byte)0xd5,
		(byte)0x37, (byte)0x3d, (byte)0x00, (byte)0xd6,
		(byte)0x71, (byte)0x67, (byte)0x59, (byte)0x06,
		(byte)0x93, (byte)0x4d, (byte)0xad, (byte)0x0f,
		(byte)0x7f, (byte)0x6c, (byte)0xed, (byte)0xda,
		(byte)0x65, (byte)0xb4, (byte)0x33, (byte)0x68,
		(byte)0xf8, (byte)0x3b, (byte)0xae, (byte)0x26,
		(byte)0xda, (byte)0xc4, (byte)0x84, (byte)0xf0,
		(byte)0x00, (byte)0x31, (byte)0x8d, (byte)0xbb,
		(byte)0x74, (byte)0x80, (byte)0x22, (byte)0x5c,
		(byte)0xe6, (byte)0x0e, (byte)0xbf, (byte)0x3a,
		(byte)0x75, (byte)0xec, (byte)0xa3, (byte)0x65,
		(byte)0x6f, (byte)0xc5, (byte)0xa0, (byte)0x85,
		(byte)0xf0, (byte)0xf3, (byte)0x4e, (byte)0xcf,
		(byte)0xa9, (byte)0xcb, (byte)0x72, (byte)0x1b,
		(byte)0xdb, (byte)0xd8, (byte)0xea, (byte)0x37,
		(byte)0xb1, (byte)0xd8, (byte)0x63, (byte)0x42,
		(byte)0x2c, (byte)0x62, (byte)0x8c, (byte)0x73,
		(byte)0x38, (byte)0x5d, (byte)0x90, (byte)0x65,
		(byte)0x4a, (byte)0xa1, (byte)0xd0, (byte)0x7b,
		(byte)0x1a, (byte)0x59, (byte)0xf6, (byte)0x23,
		(byte)0x42, (byte)0x94, (byte)0x0b, (byte)0xb4,
		(byte)0x8f, (byte)0xb0, (byte)0x5b, (byte)0x31,
		(byte)0x47, (byte)0xc9, (byte)0x4c, (byte)0x57,
		(byte)0xd7, (byte)0x90, (byte)0xae, (byte)0xc7,
		(byte)0x49, (byte)0x93, (byte)0x3a, (byte)0x2a,
		(byte)0x19, (byte)0xfe, (byte)0xc9, (byte)0x95,
		(byte)0x45, (byte)0x37, (byte)0x6e, (byte)0x87,
		(byte)0x68, (byte)0x16, (byte)0xeb, (byte)0x2a,
		(byte)0x76, (byte)0xac, (byte)0x56, (byte)0x9d,
		(byte)0x08, (byte)0xd8, (byte)0xe1, (byte)0xfe,
		(byte)0x51, (byte)0x81, (byte)0xdf, (byte)0xfb,
		(byte)0x97, (byte)0x52, (byte)0xb5, (byte)0xfc,
		(byte)0xe1, (byte)0xe9
	};

	public static void main(String[] args)
		throws Exception
	{
		new SelfTest().process();
	}

	private BigInteger modulus;
	private MakwaPrivateKey privKey;

	private void process()
		throws Exception
	{
		/*
		 * Check encoding and decoding of public and private keys.
		 */
		modulus = MakwaPrivateKey.decodePublic(PUB2048);
		privKey = new MakwaPrivateKey(PRIV2048);
		check(modulus.equals(privKey.getModulus()));
		check(equals(privKey.exportPrivate(), PRIV2048));
		check(equals(privKey.exportPublic(), PUB2048));
		check(modulus.equals(MakwaPrivateKey.decodePublic(PUB2048)));

		System.out.println("Simple API...");
		checkSimple(false, 0, 384);
		checkSimple(false, 12, 384);
		checkSimple(true, 0, 384);
		checkSimple(true, 12, 384);
		checkSimple(false, 0, 4096);
		checkSimple(false, 12, 4096);
		checkSimple(true, 0, 4096);
		checkSimple(true, 12, 4096);

		System.out.println("Work factor change...");
		checkWFChange();

		System.out.println("Unescrow...");
		checkUnescrow();

		System.out.println("Delegation...");
		checkDelegation();

		System.out.println("PHC API...");
		checkPHC();

		System.out.println("Speed test...");
		speedTest();

		System.out.println("All tests OK.");
	}

	private void checkSimple(boolean preHash,
		int postHashLength, int workFactor)
	{
		Makwa mpub = new Makwa(modulus, Makwa.SHA256,
			preHash, postHashLength, workFactor);
		Makwa mpriv = new Makwa(privKey, Makwa.SHA256,
			preHash, postHashLength, workFactor);

		String h1 = mpub.hashNewPassword("test1");
		check(mpub.verifyPassword("test1", h1));
		check(mpriv.verifyPassword("test1", h1));
		check(!mpub.verifyPassword("test2", h1));
		check(!mpriv.verifyPassword("test2", h1));
		String h2 = mpriv.hashNewPassword("test1");
		check(mpub.verifyPassword("test1", h2));
		check(mpriv.verifyPassword("test1", h2));
		check(!mpub.verifyPassword("test2", h2));
		check(!mpriv.verifyPassword("test2", h2));

		// Since each hash value uses its own salt, the strings
		// ought to be different.
		check(!h1.equals(h2));
	}

	private void checkWFChange()
	{
		Makwa mpubSmall = new Makwa(modulus, Makwa.SHA256,
			false, 0, 384);
		Makwa mprivSmall = new Makwa(privKey, Makwa.SHA256,
			false, 0, 384);
		Makwa mpubLarge = new Makwa(modulus, Makwa.SHA256,
			false, 0, 4096);
		Makwa mprivLarge = new Makwa(privKey, Makwa.SHA256,
			false, 0, 4096);

		String hsmall = mpubSmall.hashNewPassword("test1");
		String hlarge = mpubSmall.setNewWorkFactor(hsmall, 4096);
		check(mprivLarge.verifyPassword("test1", hlarge));
		hlarge = mprivSmall.setNewWorkFactor(hsmall, 4096);
		check(mpubLarge.verifyPassword("test1", hlarge));
		hsmall = mprivLarge.setNewWorkFactor(hlarge, 384);
		check(mpubSmall.verifyPassword("test1", hsmall));
	}

	private void checkUnescrow()
		throws Exception
	{
		Makwa mpub = new Makwa(modulus, Makwa.SHA256,
			false, 0, 3072);
		Makwa mpriv = new Makwa(privKey, Makwa.SHA256,
			false, 0, 3072);

		String h = mpub.hashNewPassword("test1");
		check(equals("test1".getBytes("UTF-8"),
			mpriv.unescrow(h)));
	}

	private void checkDelegation()
	{
		MakwaDelegation md = MakwaDelegation.generate(
			PRIV2048, 4096);
		byte[] mdEnc = md.export();
		md = new MakwaDelegation(mdEnc);
		Makwa mpub = new Makwa(modulus, Makwa.SHA256,
			false, 0, 4096);
		Makwa mpriv = new Makwa(privKey, Makwa.SHA256,
			false, 0, 4096);

		Makwa.DelegationContext dc =
			mpub.hashNewPasswordDelegate("test1", md);
		byte[] req = dc.getRequest();
		byte[] ans = Makwa.processDelegationRequest(req);
		String h = dc.doFinalToString(ans);
		check(mpriv.verifyPassword("test1", h));

		dc = mpub.verifyPasswordDelegate("test1", h, md);
		req = dc.getRequest();
		ans = Makwa.processDelegationRequest(req);
		check(dc.doFinalVerify(ans));
	}

	private void checkPHC()
		throws Exception
	{
		/*
		 * Since the PHC rules talk only about C, not Java, there
		 * is no "PHC-compliant API" in Java. However, we can still
		 * check a test vector.
		 */
		byte[] salt = new byte[] { 1, 2, 3, 4 };
		byte[] input = "sample for PHC".getBytes("UTF-8");
		Makwa m = new Makwa(PHC_PUB2048, 0, false, 0, 4096);
		byte[] out = m.doHash(input, salt, true, 16, 8192);
		byte[] ref = new byte[] {
			(byte)0x1d, (byte)0x4f, (byte)0x1b, (byte)0x05,
			(byte)0x58, (byte)0xe9, (byte)0x60, (byte)0xce,
			(byte)0x11, (byte)0xad, (byte)0xd5, (byte)0x20,
			(byte)0xca, (byte)0x9e, (byte)0x28, (byte)0xf3
		};
		check(equals(out, ref));
	}

	private void speedTest()
	{
		Makwa mpub = new Makwa(modulus, Makwa.SHA256,
			false, 0, 4096);
		int wprev = 1;
		int w = 2;
		long ttprev = 0;
		byte[] input = new byte[9];
		for (;;) {
			long begin = System.currentTimeMillis();
			byte[] salt = Makwa.createSalt();
			mpub.doHash(input, salt, true, 16, w);
			long end = System.currentTimeMillis();
			long tt = end - begin;
			if (tt > 4000) {
				System.out.printf("wf/s = %.2f",
					(1000.0 * (w - wprev)) / (tt - ttprev));
				System.out.println();
				break;
			}
			ttprev = tt;
			wprev = w;
			w <<= 1;
		}

		Makwa mpriv = new Makwa(PRIV2048, 0, true, 16, 65536);
		String ref = mpriv.hashNewPassword("speedtest");
		int cc = 2;
		for (;;) {
			long begin = System.currentTimeMillis();
			for (int m = 0; m < cc; m ++) {
				mpriv.verifyPassword("speedtest", ref);
			}
			long end = System.currentTimeMillis();
			long tt = end - begin;
			if (tt > 4000) {
				System.out.printf("priv/s = %.2f",
					(1000.0 * cc) / tt);
				System.out.println();
				break;
			}
			cc <<= 1;
		}
	}

	private static void check(boolean v)
	{
		if (!v) {
			throw new MakwaException("self-test failed");
		}
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
}
