package com.dotcms.saml.service.handler;

import com.dotcms.saml.IdentityProviderConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Encapsulates the Authentication Handler, could be POST or Redirect (default)
 * @author jsanca
 */
public interface AuthenticationHandler {

    /**
     * Handles the authentication method
     * @param request    HttpServletRequest
     * @param response  {@link HttpServletResponse}
     * @param idpConfig {@link IdentityProviderConfiguration}
     */
    void handle(final HttpServletRequest request, final HttpServletResponse response, final IdentityProviderConfiguration idpConfig);
}
