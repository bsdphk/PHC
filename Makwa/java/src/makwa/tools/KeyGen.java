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

import java.io.FileOutputStream;
import java.io.IOException;

import makwa.Makwa;
import makwa.MakwaPrivateKey;

/**
 * <p>This command-line tools generates key pairs for Makwa. Usage:</p>
 * <pre>
 *    KeyGen size [ -text ] [ -outpub file ] [ -outpriv file ]
 * </pre>
 *
 * <p>The {@code size} parameter is the modulus size, in bits. It must be
 * in the 1273 to 32768 range. The recommended value is 2048.</p>
 *
 * <p>If {@code -text} is specified, then the modulus will be displayed
 * (in hexadecimal).</p>
 *
 * <p>If {@code -outpub} is used, then the public key (modulus) is encoded
 * and written into a file with the provided name.</p>
 *
 * <p>If {@code -outpriv} is used, then the private key is encoded
 * and written into a file with the provided name. If this option is not
 * used, then the private key is lost forever; this does not prevent the
 * modulus from being used with Makwa, but the "fast path", work factor
 * decrease and unescrow features will never be usable with that modulus.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin
 */

public class KeyGen {

	public static void main(String[] args)
		throws IOException
	{
		boolean textOut = false;
		String outPub = null;
		String outPriv = null;
		int size = 0;
		for (int i = 0; i < args.length; i ++) {
			String a = args[i];
			if (a.equalsIgnoreCase("-text")) {
				if (textOut) {
					usage();
				}
				textOut = true;
			} else if (a.equalsIgnoreCase("-outpub")) {
				if (++ i >= args.length) {
					usage();
				}
				if (outPub != null) {
					usage();
				}
				outPub = args[i];
			} else if (a.equalsIgnoreCase("-outpriv")) {
				if (++ i >= args.length) {
					usage();
				}
				if (outPriv != null) {
					usage();
				}
				outPriv = args[i];
			} else {
				if (size != 0) {
					usage();
				}
				try {
					size = Integer.parseInt(a);
				} catch (NumberFormatException nfe) {
					usage();
				}
				if (size < 1273 || size > 32768) {
					usage();
				}
			}
		}
		if (size == 0) {
			usage();
		}
		MakwaPrivateKey pkey = MakwaPrivateKey.generate(size);
		if (textOut) {
			System.out.println("modulus = 0x"
				+ pkey.getModulus().toString(16).toUpperCase());
		}
		if (outPub != null) {
			FileOutputStream out = new FileOutputStream(outPub);
			try {
				out.write(pkey.exportPublic());
			} finally {
				out.close();
			}
		}
		if (outPriv != null) {
			FileOutputStream out = new FileOutputStream(outPriv);
			try {
				out.write(pkey.exportPrivate());
			} finally {
				out.close();
			}
		}
	}

	private static void usage()
	{
		System.err.println(
"usage: KeyGen size [ -text ] [ -outpub file ] [ -outpriv file ]");
		System.exit(1);
	}
}
