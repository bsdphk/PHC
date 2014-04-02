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

/**
 * A {@code MakwaException} is thrown for any error during Makwa
 * processing.
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class MakwaException extends RuntimeException {

	/**
	 * Create an instance.
	 */
	public MakwaException()
	{
		super();
	}

	/**
	 * Create an instance with an explicit message.
	 *
	 * @param message   the message
	 */
	public MakwaException(String message)
	{
		super(message);
	}

	/**
	 * Create an instance with a cause (nexted exception).
	 *
	 * @param cause   the cause
	 */
	public MakwaException(Exception cause)
	{
		super(cause);
	}

	/**
	 * Create an instance with an explicit message and a cause
	 * (nexted exception).
	 *
	 * @param message   the message
	 * @param cause     the cause
	 */
	public MakwaException(String message, Exception cause)
	{
		super(message, cause);
	}
}
