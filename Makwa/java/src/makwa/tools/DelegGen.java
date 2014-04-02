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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import makwa.MakwaDelegation;

/**
 * <p>This command-line tools generates sets of parameters for Makwa
 * delegation. Usage:</p>
 * <pre>
 *    DelegGen inParam workFactor outFile
 * </pre>
 *
 * <p>The {@code inParam} parameter is the name of a file containing an
 * encoded Makwa modulus, or an encoded Makwa private key. Processing
 * is (much) faster if a private key is used; but the obtained set is
 * equally valid otherwise.</p>
 *
 * <p>The {@code workFactor} parameter is the work factor for which the
 * set of parameters is created. Each set of parameters is specific to a
 * single work factor.</p>
 *
 * <p>The resulting set of parameters is finally encoded into the
 * file whose name is provided as {@code outFile}.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin
 */

public class DelegGen {

	public static void main(String[] args)
		throws IOException
	{
		if (args.length != 3) {
			usage();
		}
		byte[] mparam = readAllBytes(args[0]);
		int workFactor = Integer.parseInt(args[1]);
		MakwaDelegation md = MakwaDelegation.generate(
			mparam, workFactor);
		FileOutputStream out = new FileOutputStream(args[2]);
		try {
			out.write(md.export());
		} finally {
			out.close();
		}
	}

	private static void usage()
	{
		System.err.println(
"usage: DelegGen inParam workFactor outFile");
		System.exit(1);
	}

	private static byte[] readAllBytes(String name)
		throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[8192];
		FileInputStream in = new FileInputStream(name);
		try {
			for (;;) {
				int len = in.read(buf);
				if (len < 0) {
					return baos.toByteArray();
				}
				baos.write(buf, 0, len);
			}
		} finally {
			in.close();
		}
	}
}
