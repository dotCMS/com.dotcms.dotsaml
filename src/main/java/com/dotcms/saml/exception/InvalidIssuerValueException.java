package com.dotcms.saml.exception;

/**
 * Exception to report an issue with the issuer value.
 * 
 * @author jsanca
 */

public class InvalidIssuerValueException extends RuntimeException
{
	private static final long serialVersionUID = 2963820217308468676L;

	public InvalidIssuerValueException( String message )
	{
		super( message );
	}
}
