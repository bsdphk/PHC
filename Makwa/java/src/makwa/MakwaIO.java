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

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * This class contains some utility methods for I/O.
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

final class MakwaIO {

	static final int MAGIC_PUBKEY = 0x55414D30;
	static final int MAGIC_PRIVKEY = 0x55414D31;
	static final int MAGIC_DELEG_PARAM = 0x55414D32;
	static final int MAGIC_DELEG_REQ = 0x55414D33;
	static final int MAGIC_DELEG_ANS = 0x55414D34;

	static int read8(InputStream in)
		throws IOException
	{
		int x = in.read();
		if (x < 0) {
			throw new EOFException();
		}
		return x;
	}

	static int read16(InputStream in)
		throws IOException
	{
		int h = read8(in);
		int l = read8(in);
		return (h << 8) + l;
	}

	static int read32(InputStream in)
		throws IOException
	{
		int h = read16(in);
		int l = read16(in);
		return (h << 16) + l;
	}

	static void readAll(InputStream in, byte[] buf)
		throws IOException
	{
		readAll(in, buf, 0, buf.length);
	}

	static void write8(OutputStream out, int x)
		throws IOException
	{
		out.write(x);
	}

	static void write16(OutputStream out, int x)
		throws IOException
	{
		out.write(x >>> 8);
		out.write(x);
	}

	static void write32(OutputStream out, int x)
		throws IOException
	{
		out.write(x >>> 24);
		out.write(x >>> 16);
		out.write(x >>> 8);
		out.write(x);
	}

	static void readAll(InputStream in, byte[] buf, int off, int len)
		throws IOException
	{
		while (len > 0) {
			int rlen = in.read(buf, off, len);
			if (rlen < 0) {
				throw new EOFException();
			}
			off += rlen;
			len -= rlen;
		}
	}

	static void writeMPI(OutputStream out, BigInteger v)
		throws IOException
	{
		if (v.signum() < 0) {
			throw new MakwaException(
				"cannot encode MPI: negative");
		}
		byte[] buf = v.toByteArray();
		int off;
		if (buf[0] == 0x00 && buf.length > 1) {
			off = 1;
		} else {
			off = 0;
		}
		int len = buf.length - off;
		if (len > 0xFFFF) {
			throw new MakwaException(
				"cannot encode MPI: too large");
		}
		out.write(len >>> 8);
		out.write(len & 0xFF);
		out.write(buf, off, len);
	}

	static BigInteger readMPI(InputStream in)
		throws IOException
	{
		int len = read16(in);
		byte[] buf = new byte[len];
		readAll(in, buf);
		return new BigInteger(1, buf);
	}
}
