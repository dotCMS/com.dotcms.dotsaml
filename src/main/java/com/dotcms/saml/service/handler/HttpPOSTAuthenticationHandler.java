package com.dotcms.saml.service.handler;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.service.external.SamlException;
import com.dotcms.saml.service.impl.DotHTTPPOSTDeflateEncoder;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.SamlUtils;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implements the authentication handler by POST
 * @author jsanca
 */
public class HttpPOSTAuthenticationHandler implements AuthenticationHandler {

    private final SamlCoreService samlCoreService;
    private final VelocityEngine  velocityEngine;
    private final MessageObserver messageObserver;

    public HttpPOSTAuthenticationHandler(final SamlCoreService samlCoreService,
                                         final VelocityEngine velocityEngine,
                                         final MessageObserver messageObserver) {

        this.samlCoreService = samlCoreService;
        this.velocityEngine  = velocityEngine;
        this.messageObserver = messageObserver;
    }

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response, final IdentityProviderConfiguration idpConfig) {

        final MessageContext context    = new MessageContext(); // main context
        final AuthnRequest authnRequest = this.samlCoreService.buildAuthnRequest(request, idpConfig, SAMLConstants.SAML2_POST_BINDING_URI);

        context.setMessage(authnRequest);

        // peer entity (Idp to SP and viceversa)
        final SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        // info about the endpoint of the peer entity
        final SAMLEndpointContext endpointContext     = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        endpointContext.setEndpoint(this.samlCoreService.getIdentityProviderDestinationEndpoint(idpConfig));

        this.setSignatureSigningParams(context, idpConfig);
        this.doPost(context, response, authnRequest, idpConfig);
    }

    private void setSignatureSigningParams(final MessageContext context, final IdentityProviderConfiguration idpConfig) {

        final SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();

        signatureSigningParameters.setSigningCredential(this.samlCoreService.getCredential(idpConfig));
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);
    }

    // this makes the post to the IdP
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void doPost(final MessageContext context, final HttpServletResponse response,
                        final XMLObject xmlObject, final IdentityProviderConfiguration idpConfig) {
        final HTTPPostEncoder encoder;

        try {
            encoder = new DotHTTPPOSTDeflateEncoder(this.velocityEngine);

            encoder.setMessageContext(context);
            encoder.setHttpServletResponse(response);

            encoder.initialize();

            this.messageObserver.updateDebug(this.getClass(), "Printing XMLObject:");
            this.messageObserver.updateDebug(this.getClass(), "\n\n" + SamlUtils.toXMLObjectString(xmlObject));
            this.messageObserver.updateDebug(this.getClass(), "Posting to IdP '" + idpConfig.getIdpName() + "'");


            encoder.encode();
        } catch (ComponentInitializationException | MessageEncodingException e) {

            final String errorMsg = "An error occurred when executing Posting to IdP '" +
                    idpConfig.getIdpName() + "': " + e.getMessage();
            this.messageObserver.updateError(this.getClass(), errorMsg, e);
            throw new SamlException(errorMsg, e);
        }
    }
}