package com.dotcms.saml.service.handler;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlName;
import com.dotcms.saml.service.external.SamlException;
import com.dotcms.saml.service.impl.DotHTTPRedirectDeflateEncoder;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.SamlUtils;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implements the authentication handler by redirect
 * @author jsanca
 */
public class HttpRedirectAuthenticationHandler implements AuthenticationHandler {

    private final SamlCoreService samlCoreService;
    private final MessageObserver messageObserver;
    private final SamlConfigurationService samlConfigurationService;


    public HttpRedirectAuthenticationHandler(final SamlCoreService samlCoreService,
                                             final MessageObserver messageObserver,
                                             final SamlConfigurationService samlConfigurationService) {

        this.samlCoreService = samlCoreService;
        this.messageObserver = messageObserver;
        this.samlConfigurationService = samlConfigurationService;
    }

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response, final IdentityProviderConfiguration identityProviderConfiguration) {

        final MessageContext context    = new MessageContext(); // main context
        final AuthnRequest authnRequest = this.samlCoreService.buildAuthnRequest(request, identityProviderConfiguration);

        context.setMessage(authnRequest);

        // peer entity (Idp to SP and viceversa)
        final SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        // info about the endpoint of the peer entity
        final SAMLEndpointContext endpointContext     = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        endpointContext.setEndpoint(this.samlCoreService.getIdentityProviderDestinationEndpoint(identityProviderConfiguration));

        this.setSignatureSigningParams(context, identityProviderConfiguration);
        this.doRedirect(context, response, authnRequest, identityProviderConfiguration);
    }

    @SuppressWarnings("rawtypes")
    protected void setSignatureSigningParams(final MessageContext context,
                                             final IdentityProviderConfiguration identityProviderConfiguration) {

        final SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();

        signatureSigningParameters.setSigningCredential(this.samlCoreService.getCredential(identityProviderConfiguration));
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);
    }

    // this makes the redirect to the IdP
    @SuppressWarnings({ "rawtypes", "unchecked" })
    protected void doRedirect(final MessageContext context, final HttpServletResponse response,
                              final XMLObject xmlObject,
                              final IdentityProviderConfiguration identityProviderConfiguration) {

        final boolean clearQueryParams = samlConfigurationService.getConfigAsBoolean(identityProviderConfiguration,
                SamlName.DOTCMS_SAML_CLEAR_LOCATION_QUERY_PARAMS);

        try {

            final HTTPRedirectDeflateEncoder encoder = new DotHTTPRedirectDeflateEncoder(
                    clearQueryParams, this.messageObserver);

            encoder.setMessageContext(context);
            encoder.setHttpServletResponse(response);

            encoder.initialize();

            this.messageObserver.updateDebug(this.getClass().getName(), "Printing XMLObject:");
            this.messageObserver.updateDebug(this.getClass().getName(), "\n\n" + SamlUtils.toXMLObjectString(xmlObject));
            this.messageObserver.updateDebug(this.getClass().getName(), "Redirecting to IdP '" + identityProviderConfiguration.getIdpName() + "'");

            encoder.encode();
        } catch (ComponentInitializationException | MessageEncodingException e) {

            final String errorMsg = "An error occurred when executing redirect to IdP '" +
                    identityProviderConfiguration.getIdpName() + "': " + e.getMessage();
            this.messageObserver.updateError(this.getClass().getName(), errorMsg, e);
            throw new SamlException(errorMsg, e);
        }
    }

}
