package com.dotcms.saml.utils;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.service.external.SamlConstants;
import com.dotcms.saml.service.external.SamlException;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.regex.Pattern;

/**
 * Remembers, in the user's browser, the authentication requests dotCMS sent to the IdP, so the
 * SAML Response that comes back can be bound to the request that caused it (InResponseTo).
 *
 * The IdP returns the user with a cross-site POST, and the session cookie is SameSite=Lax by default, so
 * the HTTP session is not available on that request. A short-lived, HttpOnly, SameSite=None cookie per
 * request ID is sent on that POST instead. A response whose InResponseTo has no matching cookie was not
 * started from this browser and is rejected.
 *
 * @author dotCMS
 */
public final class AuthnRequestStateCookie {

    public static final String COOKIE_PREFIX = "dotsaml_req_";

    private static final Pattern SAFE_TOKEN = Pattern.compile("[A-Za-z0-9_-]{1,128}");
    private static final int MIN_MAX_AGE_SECONDS = 60;
    private static final int MAX_MAX_AGE_SECONDS = 3600;

    private AuthnRequestStateCookie() {
        // utility class
    }

    /**
     * Records an outstanding authentication request for the IdP configuration.
     *
     * @param response                      {@link HttpServletResponse} that redirects or posts to the IdP
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param requestId                     the AuthnRequest ID
     */
    public static void remember(final HttpServletResponse response,
                                final IdentityProviderConfiguration identityProviderConfiguration,
                                final String requestId) {

        if (!isSafeToken(requestId) || !isSafeToken(identityProviderConfiguration.getId())) {

            throw new SamlException("Can not record the authentication request for IdP '"
                    + identityProviderConfiguration.getIdpName() + "'");
        }

        response.addHeader("Set-Cookie", buildCookie(requestId, identityProviderConfiguration.getId(),
                getMaxAgeSeconds(identityProviderConfiguration)));
    }

    /**
     * Returns true when this browser has an outstanding authentication request with the given ID for the
     * IdP configuration, and clears it so the same request can not be answered twice.
     *
     * @param request                       {@link HttpServletRequest} carrying the SAML Response
     * @param response                      {@link HttpServletResponse}
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param requestId                     the InResponseTo value of the SAML Response
     * @return boolean
     */
    public static boolean consume(final HttpServletRequest request, final HttpServletResponse response,
                                  final IdentityProviderConfiguration identityProviderConfiguration,
                                  final String requestId) {

        final Cookie[] cookies = request.getCookies();
        if (!isSafeToken(requestId) || null == cookies) {

            return false;
        }

        final String cookieName = COOKIE_PREFIX + requestId;
        for (final Cookie cookie : cookies) {

            if (cookieName.equals(cookie.getName())
                    && StringUtils.equals(identityProviderConfiguration.getId(), cookie.getValue())) {

                response.addHeader("Set-Cookie", buildCookie(requestId, StringUtils.EMPTY, 0));
                return true;
            }
        }

        return false;
    }

    static int getMaxAgeSeconds(final IdentityProviderConfiguration identityProviderConfiguration) {

        int maxAge = SamlConstants.AUTHN_REQUEST_MAX_AGE_DEFAULT_VALUE;
        if (identityProviderConfiguration.containsOptionalProperty(SamlConstants.AUTHN_REQUEST_MAX_AGE)) {

            try {
                maxAge = Integer.parseInt(String.valueOf(
                        identityProviderConfiguration.getOptionalProperty(SamlConstants.AUTHN_REQUEST_MAX_AGE)).trim());
            } catch (NumberFormatException e) {
                maxAge = SamlConstants.AUTHN_REQUEST_MAX_AGE_DEFAULT_VALUE;
            }
        }

        return Math.max(MIN_MAX_AGE_SECONDS, Math.min(MAX_MAX_AGE_SECONDS, maxAge));
    }

    private static String buildCookie(final String requestId, final String value, final int maxAgeSeconds) {

        return COOKIE_PREFIX + requestId + "=" + value + "; Max-Age=" + maxAgeSeconds
                + "; Path=/; Secure; HttpOnly; SameSite=None";
    }

    private static boolean isSafeToken(final String value) {

        return null != value && SAFE_TOKEN.matcher(value).matches();
    }
}
