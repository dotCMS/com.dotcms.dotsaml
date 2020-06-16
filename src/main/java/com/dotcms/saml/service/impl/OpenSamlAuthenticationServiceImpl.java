package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.external.AttributesNotFoundException;
import com.dotcms.saml.service.external.IdentityProviderConfiguration;
import com.dotcms.saml.service.external.MessageObserver;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.external.NotNullEmailAllowedException;
import com.dotcms.saml.service.external.SamlAuthenticationService;
import com.dotcms.saml.service.external.SamlConfigurationService;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.service.external.SamlException;
import com.dotcms.saml.service.external.SamlUnauthorizedException;
import com.dotcms.saml.service.external.Attributes;
import com.dotcms.saml.service.external.SamlName;
import com.dotcms.saml.service.handler.AssertionResolverHandler;
import com.dotcms.saml.service.handler.AssertionResolverHandlerFactory;
import com.dotcms.saml.utils.MetaDataXMLPrinter;
import com.dotcms.saml.utils.SamlUtils;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.commons.lang.StringUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.Writer;
import java.util.Map;

/**
 * Open Saml implementation
 * @author jsanca
 */
public class OpenSamlAuthenticationServiceImpl implements SamlAuthenticationService {

    private final AssertionResolverHandlerFactory assertionResolverHandlerFactory;
    private final SamlCoreService                 samlCoreService;
    private final SamlConfigurationService        samlConfigurationService;
    private final MessageObserver                 messageObserver;
    private final MetaDescriptorService           metaDescriptorService;
    private final MetaDataXMLPrinter              metaDataXMLPrinter;
    private final Initializer                     initializer;

    public OpenSamlAuthenticationServiceImpl(final AssertionResolverHandlerFactory assertionResolverHandlerFactory,
                                             final SamlCoreService samlCoreService,
                                             final SamlConfigurationService samlConfigurationService,
                                             final MessageObserver messageObserver,
                                             final MetaDescriptorService metaDescriptorService) {

        this.assertionResolverHandlerFactory = assertionResolverHandlerFactory;
        this.samlCoreService          = samlCoreService;
        this.samlConfigurationService = samlConfigurationService;
        this.messageObserver          = messageObserver;
        this.metaDescriptorService    = metaDescriptorService;
        this.metaDataXMLPrinter       = new MetaDataXMLPrinter();
        this.initializer              = new SamlInitializer(this.messageObserver);
    }

    @Override
    public void initService (final Map<String, Object> context) {

        if (!this.initializer.isInitializationDone()) {

            this.messageObserver.updateInfo(this.getClass(), "InitService now...");
            this.initializer.init(context);
        } else {

            this.messageObserver.updateInfo(this.getClass(), "Saml Services were already started.");
        }
    }

    @Override
    public boolean isValidSamlRequest(final HttpServletRequest  request,
                                      final HttpServletResponse response,
                                      final IdentityProviderConfiguration identityProviderConfiguration) {

        final AssertionResolverHandler assertionResolverHandler = this.assertionResolverHandlerFactory
                .getAssertionResolverForSite(identityProviderConfiguration);

        return assertionResolverHandler.isValidSamlRequest(request, response, identityProviderConfiguration);
    }

    @Override
    public void authentication(final HttpServletRequest  request,
                               final HttpServletResponse response,
                               final IdentityProviderConfiguration identityProviderConfiguration) {

        final MessageContext context    = new MessageContext(); // main context
        final AuthnRequest authnRequest = this.samlCoreService.buildAuthnRequest(request, identityProviderConfiguration);

        context.setMessage(authnRequest);

        // peer entity (Idp to SP and viceversa)
        final SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        // info about the endpoint of the peer entity
        final SAMLEndpointContext endpointContext     = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        endpointContext.setEndpoint(
                this.samlCoreService.getIdentityProviderDestinationEndpoint(identityProviderConfiguration));

        this.setSignatureSigningParams(context, identityProviderConfiguration);
        this.doRedirect(context, response, authnRequest, identityProviderConfiguration);
    }

    @Override
    public void logout(final HttpServletRequest  request,
                       final HttpServletResponse response,
                       final NameID nameID,
                       final String sessionIndexValue,
                       final IdentityProviderConfiguration identityProviderConfiguration) {

        final MessageContext context      = new MessageContext(); // main context
        final LogoutRequest logoutRequest = this.samlCoreService.buildLogoutRequest(identityProviderConfiguration, nameID, sessionIndexValue);

        context.setMessage(logoutRequest);

        // peer entity (Idp to SP and viceversa)
        final SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        // info about the endpoint of the peer entity
        final SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        endpointContext.setEndpoint(this.samlCoreService
                .getIdentityProviderSLODestinationEndpoint(identityProviderConfiguration));

        this.setSignatureSigningParams(context, identityProviderConfiguration);
        this.doRedirect(context, response, logoutRequest, identityProviderConfiguration);
    }

    @Override
    public Attributes resolveAttributes(final HttpServletRequest  request,
                                        final HttpServletResponse response,
                                        final IdentityProviderConfiguration identityProviderConfiguration) {
        Attributes attributes = null;

        try {

            final Assertion assertion = this.resolveAssertion(request, response, identityProviderConfiguration);
            attributes                = this.retrieveAttributes(assertion, identityProviderConfiguration);

            this.messageObserver.updateDebug(this.getClass(), "Validating user - " + attributes);

        } catch (AttributesNotFoundException e) {

            this.messageObserver.updateError(this.getClass(), e.getMessage(), e);
        } catch (Exception e) {

            this.messageObserver.updateError(this.getClass(),
                    "An error occurred when loading user with ID '" + attributes.getNameID().getValue() + "'", e);
        }

        return attributes;
    }

    protected Assertion resolveAssertion(final HttpServletRequest request, final HttpServletResponse response,
                                      final IdentityProviderConfiguration identityProviderConfiguration) {

        final AssertionResolverHandler assertionResolverHandler = this.assertionResolverHandlerFactory
                .getAssertionResolverForSite(identityProviderConfiguration);

        return assertionResolverHandler.resolveAssertion(request, response, identityProviderConfiguration);
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

            this.messageObserver.updateDebug(this.getClass(), "Printing XMLObject:");
            this.messageObserver.updateDebug(this.getClass(), "\n\n" + SamlUtils.toXMLObjectString(xmlObject));
            this.messageObserver.updateDebug(this.getClass(), "Redirecting to IdP '" + identityProviderConfiguration.getIdpName() + "'");

            encoder.encode();
        } catch (ComponentInitializationException | MessageEncodingException e) {

            final String errorMsg = "An error occurred when executing redirect to IdP '" +
                    identityProviderConfiguration.getIdpName() + "': " + e.getMessage();
            this.messageObserver.updateError(this.getClass(), errorMsg, e);
            throw new SamlException(errorMsg, e);
        }
    }

    // resolve the attributes from the assertion resolved from the OpenSaml
    // artifact resolver via
    protected Attributes retrieveAttributes(final Assertion assertion, final IdentityProviderConfiguration identityProviderConfiguration)
            throws AttributesNotFoundException {

        final String emailField     = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration, SamlName.DOT_SAML_EMAIL_ATTRIBUTE);
        final String firstNameField = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration, SamlName.DOT_SAML_FIRSTNAME_ATTRIBUTE);
        final String lastNameField  = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration, SamlName.DOT_SAML_LASTNAME_ATTRIBUTE);
        final String rolesField     = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration, SamlName.DOT_SAML_ROLES_ATTRIBUTE);
        final String firstNameForNullValue = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,  SamlName.DOT_SAML_FIRSTNAME_ATTRIBUTE_NULL_VALUE);
        final String lastNameForNullValue  = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,  SamlName.DOT_SAML_LASTNAME_ATTRIBUTE_NULL_VALUE);
        final boolean allowNullEmail       = this.samlConfigurationService.getConfigAsBoolean(identityProviderConfiguration, SamlName.DOT_SAML_EMAIL_ATTRIBUTE_ALLOW_NULL);

        final String customConfiguration = new StringBuilder(
                SamlName.DOT_SAML_EMAIL_ATTRIBUTE.getPropertyName()).append("=").append(emailField)
                .append(",").append(SamlName.DOT_SAML_FIRSTNAME_ATTRIBUTE.getPropertyName())
                .append("=").append(firstNameField).append(",")
                .append(SamlName.DOT_SAML_LASTNAME_ATTRIBUTE.getPropertyName()).append("=")
                .append(lastNameField).append(",")
                .append(SamlName.DOT_SAML_ROLES_ATTRIBUTE.getPropertyName()).append("=")
                .append(rolesField).toString();

        final Attributes.Builder attrBuilder = new Attributes.Builder();

        this.validateAttributes(assertion);

        final String nameId = assertion.getSubject().getNameID().getValue();

        this.messageObserver.updateDebug(this.getClass(),
                "Resolving attributes - Name ID : " + assertion.getSubject().getNameID().getValue());

        attrBuilder.nameID(assertion.getSubject().getNameID());

        this.messageObserver.updateDebug(this.getClass(),
                "Elements of type AttributeStatement in assertion : " + assertion.getAttributeStatements().size());

        assertion.getAttributeStatements().forEach(attributeStatement -> {

            this.messageObserver.updateDebug(this.getClass(),
                    "Attribute Statement - local name: " + AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME + ", type: "
                            + AttributeStatement.TYPE_LOCAL_NAME + ", number of attributes: "
                            + attributeStatement.getAttributes().size());

            attributeStatement.getAttributes().forEach(attribute -> {

                this.messageObserver.updateDebug(this.getClass(),
                        "Attribute - friendly name: " + attribute.getFriendlyName() + ", name: " + attribute.getName()
                                + ", type: " + Attribute.TYPE_LOCAL_NAME + ", number of values: "
                                + attribute.getAttributeValues().size());

                if ((attribute.getName() != null && attribute.getName().equals(emailField))
                        || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(emailField))) {

                    this.resolveEmail(emailField, attrBuilder, attribute, nameId, allowNullEmail);
                } else if ((attribute.getName() != null && attribute.getName().equals(lastNameField))
                        || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(lastNameField))) {

                    this.messageObserver.updateDebug(this.getClass(),
                            "Resolving attribute - LastName : " + lastNameField);

                    final String lastName = StringUtils.isNotBlank(
                            attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue())
                            ? attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue()
                            : checkDefaultValue(lastNameForNullValue, lastNameField + " attribute is null",
                            lastNameField + " is null and the default is null too");

                    attrBuilder.lastName(lastName);

                    this.messageObserver.updateDebug(this.getClass(),
                            "Resolved attribute - lastName : " + attrBuilder.getLastName());
                } else if ((attribute.getName() != null && attribute.getName().equals(firstNameField))
                        || (attribute.getFriendlyName() != null
                        && attribute.getFriendlyName().equals(firstNameField))) {

                    this.messageObserver.updateDebug(this.getClass(),
                            "Resolving attribute - firstName : " + firstNameField);

                    final String firstName = StringUtils.isNotBlank(
                            attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue())
                            ? attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue()
                            : checkDefaultValue(firstNameForNullValue, firstNameField + " attribute is null",
                            firstNameField + " is null and the default is null too");

                    attrBuilder.firstName(firstName);

                    this.messageObserver.updateDebug(this.getClass(),
                            "Resolved attribute - firstName : " + attrBuilder.getFirstName());
                } else if ((attribute.getName() != null && attribute.getName().equals(rolesField))
                        || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(rolesField))) {

                    this.messageObserver.updateDebug(this.getClass(), "Resolving attribute - roles : " + rolesField);
                    attrBuilder.addRoles(true).roles(attribute);
                    this.messageObserver.updateDebug(this.getClass(), "Resolving attributes - roles : " + attribute);
                } else {

                    final String attributeName = attribute.getName();
                    this.messageObserver.updateWarning(this.getClass(),
                            attributeName + " attribute did not match any user property in the idpConfig: " + customConfiguration);
                }
            });
        });

        Attributes attributes = attrBuilder.build();
        this.messageObserver.updateDebug(this.getClass(), "-> Value of attributesBean = " + attributes.toString());
        attributes = this.doubleCheckAttributes(attributes, firstNameField, firstNameForNullValue, lastNameField,
                lastNameForNullValue, allowNullEmail);
        this.messageObserver.updateDebug(this.getClass(), "-> Double Checked attributes = " + attributes);

        return attributes;
    }

    private Attributes doubleCheckAttributes(final Attributes originalAttributes, final String firstNameField,
                                                 final String firstNameForNullValue, final String lastNameField, final String lastNameForNullValue,
                                                 final boolean allowNullEmail) {
        return (this.anyAttributeNullOrBlank(originalAttributes)) ? this.checkDefaultValues(originalAttributes,
                firstNameField, firstNameForNullValue, lastNameField, lastNameForNullValue, allowNullEmail)
                : originalAttributes;
    }

    private Attributes checkDefaultValues(final Attributes originalAttributes, final String firstNameField,
                                              final String firstNameForNullValue, final String lastNameField, final String lastNameForNullValue,
                                              final boolean allowNullEmail) {
        final Attributes.Builder attrBuilder = new Attributes.Builder();

        attrBuilder.nameID(originalAttributes.getNameID());
        attrBuilder.roles(originalAttributes.getRoles());
        attrBuilder.addRoles(originalAttributes.isAddRoles());

        if (StringUtils.isBlank((originalAttributes.getEmail()))) {

            attrBuilder.email(this.createNoReplyEmail(originalAttributes.getNameID().getValue(), allowNullEmail));
        } else {

            attrBuilder.email(originalAttributes.getEmail());
        }

        if (StringUtils.isBlank(originalAttributes.getFirstName())) {

            attrBuilder.firstName(checkDefaultValue(firstNameForNullValue, firstNameField + " attribute is null",
                    firstNameField + " is null and the default is null too"));
        } else {

            attrBuilder.firstName(originalAttributes.getFirstName());
        }

        if (StringUtils.isBlank(originalAttributes.getLastName())) {

            attrBuilder.lastName(checkDefaultValue(lastNameForNullValue, lastNameField + " attribute is null",
                    lastNameField + " is null and the default is null too"));
        } else {

            attrBuilder.lastName(originalAttributes.getLastName());
        }

        return attrBuilder.build();
    }

    private boolean anyAttributeNullOrBlank(final Attributes originalAttributes) {
        return StringUtils.isBlank(originalAttributes.getEmail())
                || StringUtils.isBlank(originalAttributes.getFirstName())
                || StringUtils.isBlank(originalAttributes.getLastName());
    }

    protected String checkDefaultValue(final String lastNameForNullValue,
                                       final String logMessage,
                                       final String exceptionMessage) {

        if (StringUtils.isBlank(lastNameForNullValue)) {

            throw new SamlUnauthorizedException(exceptionMessage);
        }

        this.messageObserver.updateInfo(this.getClass(), logMessage);

        return lastNameForNullValue;
    }

    protected void resolveEmail(final String emailField, final Attributes.Builder attributesBuilder,
                              final Attribute attribute, final String nameId, final boolean allowNullEmail) {

        this.messageObserver.updateDebug(this.getClass(), "Resolving attribute - Email : " + emailField);

        String emailValue = attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue();

        emailValue = StringUtils.isBlank(emailValue)? createNoReplyEmail(nameId, allowNullEmail) : emailValue;

        attributesBuilder.email(emailValue);

        this.messageObserver.updateDebug(this.getClass(),  "Resolved attribute - Email : " + attributesBuilder.getEmail());
    }

    protected String createNoReplyEmail(final String nameId, final boolean allowNullEmail) {

        if (!allowNullEmail) {

            throw new NotNullEmailAllowedException("Email attribute is null, which is not allowed");
        }

        this.messageObserver.updateInfo(this.getClass(),
                "UserID '" + nameId + "' has a null email attribute. Generating one...");

        final String emailValue = new StringBuilder(NO_REPLY).append(sanitizeNameId(nameId)).append(NO_REPLY_DOTCMS_COM)
                .toString();

        this.messageObserver.updateDebug(this.getClass(),
                "UserID '" + nameId + "' has been assigned email '" + emailValue + "'");

        return emailValue;
    }

    private String sanitizeNameId(final String nameId) {

        return StringUtils.replace(nameId, AT_SYMBOL, AT_);
    }

    protected void validateAttributes(final Assertion assertion) throws AttributesNotFoundException {

        if (null == assertion) {

            throw new AttributesNotFoundException("SAML Assertion is null");
        }

        if (null == assertion.getAttributeStatements() || assertion.getAttributeStatements().isEmpty()) {

            throw new AttributesNotFoundException("Attribute list in SAML Assertion is null or empty");
        }

        if (null == assertion.getSubject()) {

            throw new AttributesNotFoundException("Subject in SAML Assertion is null");
        }

        if (null == assertion.getSubject().getNameID() || assertion.getSubject().getNameID().getValue().isEmpty()) {

            throw new AttributesNotFoundException("NameID in SAML Assertion is null or empty");
        }
    }

    @Override
    public void renderMetadataXML(final Writer writer,
                           final IdentityProviderConfiguration identityProviderConfiguration) {

        try {

            // First, get the Entity descriptor.
            final EntityDescriptor descriptor = this.metaDescriptorService.
                    getServiceProviderEntityDescriptor(identityProviderConfiguration);

            this.messageObserver.updateDebug(this.getClass(), "Printing Metadata Descriptor:");
            this.messageObserver.updateDebug(this.getClass(), "\n\n" + descriptor);
            // get ready to convert it to XML.
            this.metaDataXMLPrinter.print(descriptor, writer);

            this.messageObserver.updateDebug(this.getClass(),"Metadata Descriptor printed.");
        } catch (ParserConfigurationException | TransformerException | MarshallingException e) {

            this.messageObserver.updateError(this.getClass(), e.getMessage(), e);
            throw new SamlException(e.getMessage(), e);
        }
    }
}