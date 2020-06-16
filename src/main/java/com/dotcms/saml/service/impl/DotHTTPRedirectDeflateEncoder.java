package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.external.MessageObserver;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.xmlsec.SignatureSigningParameters;

import java.net.MalformedURLException;
import java.util.List;

public class DotHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {

    private final boolean clearQueryParams;
    private final MessageObserver messageObserver;

    public DotHTTPRedirectDeflateEncoder(final MessageObserver messageObserver) {
        this(true, messageObserver);
    }

    public DotHTTPRedirectDeflateEncoder(final boolean clearQueryParams, final MessageObserver messageObserver) {

        this.clearQueryParams = clearQueryParams;
        this.messageObserver  = messageObserver;
    }

    @Override
    protected String buildRedirectURL(final MessageContext<SAMLObject> messageContext,
                                      final String endpoint,
                                      final String message) throws MessageEncodingException {

        this.messageObserver.updateDebug(this.getClass(),
                "Building URL to redirect client to: " + endpoint);
        URLBuilder urlBuilder = null;

        try {

            urlBuilder = new URLBuilder(endpoint);
        } catch (MalformedURLException e) {

            throw new MessageEncodingException("Endpoint URL " + endpoint + " is not a valid URL", e);
        }

        final List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
        if (this.clearQueryParams) {
            queryParams.clear();
        }

        final SAMLObject outboundMessage = (SAMLObject)messageContext.getMessage();
        if (outboundMessage instanceof RequestAbstractType) {

            queryParams.add(new Pair("SAMLRequest", message));
        } else {

            if (!(outboundMessage instanceof StatusResponseType)) {

                throw new MessageEncodingException("SAML message is neither a SAML RequestAbstractType nor StatusResponseType");
            }

            queryParams.add(new Pair("SAMLResponse", message));
        }

        final String relayState = SAMLBindingSupport.getRelayState(messageContext);
        if (SAMLBindingSupport.checkRelayState(relayState)) {

            queryParams.add(new Pair("RelayState", relayState));
        }

        final SignatureSigningParameters signingParameters = SAMLMessageSecuritySupport.getContextSigningParameters(messageContext);
        if (signingParameters != null && signingParameters.getSigningCredential() != null) {

            final String sigAlgURI            = this.getSignatureAlgorithmURI(signingParameters);
            final Pair<String, String> sigAlg = new Pair("SigAlg", sigAlgURI);
            final String sigMaterial          = urlBuilder.buildQueryString();

            queryParams.add(sigAlg);
            queryParams.add(new Pair("Signature", this.generateSignature(signingParameters.getSigningCredential(), sigAlgURI, sigMaterial)));
        } else {

            this.messageObserver.updateDebug(this.getClass(),
                    "No signing credential was supplied, skipping HTTP-Redirect DEFLATE signing");
        }

        return urlBuilder.buildURL();
    }

}