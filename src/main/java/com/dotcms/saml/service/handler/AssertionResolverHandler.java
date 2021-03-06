package com.dotcms.saml.service.handler;

import com.dotcms.saml.IdentityProviderConfiguration;
import org.opensaml.saml.saml2.core.Assertion;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * This handler is in charge of resolve the user based on a saml callback
 * 
 * @author jsanca
 */
public interface AssertionResolverHandler extends Serializable {

	int DOT_SAML_CLOCK_SKEW_DEFAULT_VALUE   = 1000;
	int DOT_SAML_MESSAGE_LIFE_DEFAULT_VALUE = 2000;

	/**
	 * Returns true if it is a valid saml request.
	 *
	 * @param request {@link HttpServletRequest}
	 * @param response {@link HttpServletResponse}
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return boolean
	 */
	boolean isValidSamlRequest(final HttpServletRequest request,
							   final HttpServletResponse response,
							   final IdentityProviderConfiguration identityProviderConfiguration);

	/**
	 * Resolve the user based on a SAML callback, depending on the
	 * implementation the criteria to check if it is a saml request and how to
	 * handle might be different.
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param response {@link HttpServletResponse}
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return User
	 */
	Assertion resolveAssertion(final HttpServletRequest request,
							   final HttpServletResponse response,
							   final IdentityProviderConfiguration identityProviderConfiguration);

}
