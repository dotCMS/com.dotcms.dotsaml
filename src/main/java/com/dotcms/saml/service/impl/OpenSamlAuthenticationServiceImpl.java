package com.dotcms.saml.service.impl;

import com.dotcms.saml.Attributes;
import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.SamlAuthenticationService;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlName;
import com.dotcms.saml.service.external.AttributesNotFoundException;
import com.dotcms.saml.service.external.NotNullEmailAllowedException;
import com.dotcms.saml.service.external.SamlException;
import com.dotcms.saml.service.external.SamlUnauthorizedException;
import com.dotcms.saml.service.handler.AssertionResolverHandler;
import com.dotcms.saml.service.handler.AssertionResolverHandlerFactory;
import com.dotcms.saml.service.handler.AuthenticationHandler;
import com.dotcms.saml.service.handler.AuthenticationResolverHandlerFactory;
import com.dotcms.saml.service.handler.LogoutHandler;
import com.dotcms.saml.service.handler.LogoutResolverHandlerFactory;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.IdpConfigCredentialResolver;
import com.dotcms.saml.utils.MetaDataXMLPrinter;
import com.dotcms.saml.utils.SamlUtils;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.Logger;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.ConfigurableContentReference;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.provider.ApacheSantuarioSignerProviderImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Open Saml implementation
 * @author jsanca
 */
public class OpenSamlAuthenticationServiceImpl implements SamlAuthenticationService {

    private final LogoutResolverHandlerFactory         logoutResolverHandlerFactory;
    private final AuthenticationResolverHandlerFactory authenticationResolverHandlerFactory;
    private final AssertionResolverHandlerFactory assertionResolverHandlerFactory;
    private final SamlCoreService                 samlCoreService;
    private final SamlConfigurationService        samlConfigurationService;
    private final MessageObserver                 messageObserver;
    private final MetaDescriptorService           metaDescriptorService;
    private final MetaDataXMLPrinter              metaDataXMLPrinter;
    private final Initializer                     initializer;

    public OpenSamlAuthenticationServiceImpl(final LogoutResolverHandlerFactory logoutResolverHandlerFactory,
                                             final AuthenticationResolverHandlerFactory authenticationResolverHandlerFactory,
                                             final AssertionResolverHandlerFactory assertionResolverHandlerFactory,
                                             final SamlCoreService samlCoreService,
                                             final SamlConfigurationService samlConfigurationService,
                                             final MessageObserver messageObserver,
                                             final MetaDescriptorService metaDescriptorService,
                                             final Initializer initializer) {

        this.logoutResolverHandlerFactory         = logoutResolverHandlerFactory;
        this.authenticationResolverHandlerFactory = authenticationResolverHandlerFactory;
        this.assertionResolverHandlerFactory = assertionResolverHandlerFactory;
        this.samlCoreService          = samlCoreService;
        this.samlConfigurationService = samlConfigurationService;
        this.messageObserver          = messageObserver;
        this.metaDescriptorService    = metaDescriptorService;
        this.metaDataXMLPrinter       = new MetaDataXMLPrinter();
        this.initializer              = initializer;
    }

    @Override
    public void initService (final Map<String, Object> context) {

        if (!this.initializer.isInitializationDone()) {

            this.messageObserver.updateInfo(this.getClass().getName(), "InitService now...");
            this.initializer.init(context);
        } else {

            this.messageObserver.updateInfo(this.getClass().getName(), "Saml Services were already started.");
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


        final AuthenticationHandler authenticationHandler =
                this.authenticationResolverHandlerFactory.getAuthenticationHandlerForSite(identityProviderConfiguration);

        authenticationHandler.handle(request, response, identityProviderConfiguration);
    }

    @Override
    public void logout(final HttpServletRequest  request,
                       final HttpServletResponse response,
                       final Object nameID,
                       final String sessionIndexValue,
                       final IdentityProviderConfiguration identityProviderConfiguration) {

        final LogoutHandler logoutHandler =
            this.logoutResolverHandlerFactory.getLogoutHandlerForSite(identityProviderConfiguration);

        logoutHandler.handle(request, response, nameID, sessionIndexValue, identityProviderConfiguration);
    }


    @Override
    public Attributes resolveAttributes(final HttpServletRequest  request,
                                        final HttpServletResponse response,
                                        final IdentityProviderConfiguration identityProviderConfiguration) {
        Attributes attributes = null;

        try {

            final Assertion assertion = this.resolveAssertion(request, response, identityProviderConfiguration);
            attributes                = this.retrieveAttributes(assertion, identityProviderConfiguration);

            this.messageObserver.updateDebug(this.getClass().getName(), "Validating user - " + attributes);

        } catch (AttributesNotFoundException e) {

            this.messageObserver.updateError(this.getClass().getName(), e.getMessage(), e);
        } catch (Exception e) {

            final String nameID = null != attributes? NameID.class.cast(attributes.getNameID()).getValue(): StringUtils.EMPTY ;
            this.messageObserver.updateError(this.getClass().getName(),
                    "An error occurred when loading user with ID '" + nameID+ "'", e);
        }

        return attributes;
    }

    protected Assertion resolveAssertion(final HttpServletRequest request, final HttpServletResponse response,
                                      final IdentityProviderConfiguration identityProviderConfiguration) {

        final AssertionResolverHandler assertionResolverHandler = this.assertionResolverHandlerFactory
                .getAssertionResolverForSite(identityProviderConfiguration);

        return assertionResolverHandler.resolveAssertion(request, response, identityProviderConfiguration);
    }


    /**
     * Return the value of the /AuthnStatement@SessionIndex element in an
     * assertion
     *
     * @return The value. <code>null</code>, if the assertion does not contain
     *         the element.
     */
    protected String getSessionIndex(final Assertion assertion) {
        String sessionIndex = null;

        if (assertion != null && assertion.getAuthnStatements() != null) {
            if (assertion.getAuthnStatements().size() > 0) {
                // We only look into the first AuthnStatement
                final AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
                sessionIndex = authnStatement.getSessionIndex();
            }
        }

        return sessionIndex;
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

        this.validateAttributes(assertion, identityProviderConfiguration);

        final String nameId = assertion.getSubject().getNameID().getValue();

        this.messageObserver.updateDebug(this.getClass().getName(),
                "Resolving attributes - Name ID : " + assertion.getSubject().getNameID().getValue());

        attrBuilder.nameID(assertion.getSubject().getNameID());

        this.messageObserver.updateDebug(this.getClass().getName(),
                "Elements of type AttributeStatement in assertion : " + assertion.getAttributeStatements().size());
        if (null != assertion.getAttributeStatements()) {
            assertion.getAttributeStatements().forEach(attributeStatement -> {

                this.messageObserver.updateDebug(this.getClass().getName(),
                        "Attribute Statement - local name: " + AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME + ", type: "
                                + AttributeStatement.TYPE_LOCAL_NAME + ", number of attributes: "
                                + attributeStatement.getAttributes().size());

                attributeStatement.getAttributes().forEach(attribute -> {

                    this.messageObserver.updateDebug(this.getClass().getName(),
                            "Attribute - friendly name: " + attribute.getFriendlyName() + ", name: " + attribute.getName()
                                    + ", type: " + Attribute.TYPE_LOCAL_NAME + ", number of values: "
                                    + attribute.getAttributeValues().size());

                    if ((attribute.getName() != null && attribute.getName().equals(emailField))
                            || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(emailField))) {

                        this.resolveEmail(emailField, attrBuilder, attribute, nameId, allowNullEmail);
                    } else if ((attribute.getName() != null && attribute.getName().equals(lastNameField))
                            || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(lastNameField))) {

                        this.messageObserver.updateDebug(this.getClass().getName(),
                                "Resolving attribute - LastName : " + lastNameField);

                        final String lastName = StringUtils.isNotBlank(
                                attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue())
                                ? attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue()
                                : checkDefaultValue(lastNameForNullValue, lastNameField + " attribute is null",
                                lastNameField + " is null and the default is null too");

                        attrBuilder.lastName(lastName);

                        this.messageObserver.updateDebug(this.getClass().getName(),
                                "Resolved attribute - lastName : " + attrBuilder.getLastName());
                    } else if ((attribute.getName() != null && attribute.getName().equals(firstNameField))
                            || (attribute.getFriendlyName() != null
                            && attribute.getFriendlyName().equals(firstNameField))) {

                        this.messageObserver.updateDebug(this.getClass().getName(),
                                "Resolving attribute - firstName : " + firstNameField);

                        final String firstName = StringUtils.isNotBlank(
                                attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue())
                                ? attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue()
                                : checkDefaultValue(firstNameForNullValue, firstNameField + " attribute is null",
                                firstNameField + " is null and the default is null too");

                        attrBuilder.firstName(firstName);

                        this.messageObserver.updateDebug(this.getClass().getName(),
                                "Resolved attribute - firstName : " + attrBuilder.getFirstName());
                    } else if ((attribute.getName() != null && attribute.getName().equals(rolesField))
                            || (attribute.getFriendlyName() != null && attribute.getFriendlyName().equals(rolesField))) {

                        this.messageObserver.updateDebug(this.getClass().getName(), "Resolving attribute - roles : " + rolesField);
                        attrBuilder.addRoles(true).roles(attribute);
                        this.messageObserver.updateDebug(this.getClass().getName(), "Resolving attributes - roles : " + attribute);
                    } else {

                        final String attributeName = attribute.getName();
                        this.messageObserver.updateWarning(this.getClass().getName(),
                                attributeName + " attribute did not match any user property in the idpConfig: " + customConfiguration);
                    }
                });
            });
        }

        attrBuilder.sessionIndex(this.getSessionIndex(assertion));

        Attributes attributes = attrBuilder.build();
        this.messageObserver.updateDebug(this.getClass().getName(), "-> Value of attributesBean = " + attributes.toString());
        attributes = this.doubleCheckAttributes(attributes, firstNameField, firstNameForNullValue, lastNameField,
                lastNameForNullValue, allowNullEmail);
        this.messageObserver.updateDebug(this.getClass().getName(), "-> Double Checked attributes = " + attributes);

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
        attrBuilder.sessionIndex(originalAttributes.getSessionIndex());

        if (StringUtils.isBlank((originalAttributes.getEmail()))) {

            final NameID nameID = (NameID) originalAttributes.getNameID();
            attrBuilder.email(this.createNoReplyEmail(nameID.getValue(), allowNullEmail));
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

            throw new DotRuntimeException(exceptionMessage);
        }

        this.messageObserver.updateInfo(this.getClass().getName(), logMessage);

        return lastNameForNullValue;
    }

    protected void resolveEmail(final String emailField, final Attributes.Builder attributesBuilder,
                              final Attribute attribute, final String nameId, final boolean allowNullEmail) {

        this.messageObserver.updateDebug(this.getClass().getName(), "Resolving attribute - Email : " + emailField);

        String emailValue = attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue();

        emailValue = StringUtils.isBlank(emailValue)? createNoReplyEmail(nameId, allowNullEmail) : emailValue;

        attributesBuilder.email(emailValue);

        this.messageObserver.updateDebug(this.getClass().getName(),  "Resolved attribute - Email : " + attributesBuilder.getEmail());
    }

    protected String createNoReplyEmail(final String nameId, final boolean allowNullEmail) {

        if (!allowNullEmail) {

            throw new NotNullEmailAllowedException("Email attribute is null, which is not allowed");
        }

        this.messageObserver.updateInfo(this.getClass().getName(),
                "UserID '" + nameId + "' has a null email attribute. Generating one...");

        final String emailValue = new StringBuilder(NO_REPLY).append(sanitizeNameId(nameId)).append(NO_REPLY_DOTCMS_COM)
                .toString();

        this.messageObserver.updateDebug(this.getClass().getName(),
                "UserID '" + nameId + "' has been assigned email '" + emailValue + "'");

        return emailValue;
    }

    private String sanitizeNameId(final String nameId) {

        return StringUtils.replace(nameId, AT_SYMBOL, AT_);
    }

    protected void validateAttributes(final Assertion assertion, final IdentityProviderConfiguration identityProviderConfiguration) throws AttributesNotFoundException {

        if (null == assertion) {

            throw new DotRuntimeException("SAML Assertion is null");
        }

        final boolean allowEmptyAttrs = identityProviderConfiguration.containsOptionalProperty("saml.allow.empty.attrs")?
                Boolean.parseBoolean(identityProviderConfiguration.getOptionalProperty("saml.allow.empty.attrs").toString()): true;
        this.samlConfigurationService.getConfigAsBoolean(identityProviderConfiguration, SamlName.DOT_SAML_EMAIL_ATTRIBUTE);
        if (null == assertion.getAttributeStatements() || assertion.getAttributeStatements().isEmpty()) {

            if (allowEmptyAttrs) {

                Logger.info(this.getClass().getName(), "SAML: Attributes are empty");
            } else {
                throw new DotRuntimeException("Attribute list in SAML Assertion is null or empty");
            }
        }

        if (null == assertion.getSubject()) {

            throw new DotRuntimeException("Subject in SAML Assertion is null");
        }

        if (null == assertion.getSubject().getNameID() || assertion.getSubject().getNameID().getValue().isEmpty()) {

            throw new DotRuntimeException("NameID in SAML Assertion is null or empty");
        }
    }

    @Override
    public void renderMetadataXML(final Writer writer,
                           final IdentityProviderConfiguration identityProviderConfiguration) {

        try {

            // First, get the Entity descriptor.
            final EntityDescriptor descriptor = this.metaDescriptorService.
                    getServiceProviderEntityDescriptor(identityProviderConfiguration);

            this.messageObserver.updateDebug(this.getClass().getName(), "Printing Metadata Descriptor:");
            this.messageObserver.updateDebug(this.getClass().getName(), "\n\n" + descriptor);
            // get ready to convert it to XML.
            this.metaDataXMLPrinter.print(descriptor, writer);

            this.messageObserver.updateDebug(this.getClass().getName(),"Metadata Descriptor printed.");
        } catch (Exception e) {

            this.messageObserver.updateError(this.getClass().getName(), e.getMessage(), e);
            throw new DotRuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String getValue(final Object samlObject) {

        if (samlObject instanceof NameID) {

            return NameID.class.cast(samlObject).getValue();
        } else if (samlObject instanceof XMLObject) {
            return XMLObject.class.cast(samlObject).getDOM().getFirstChild().getNodeValue();
        }

        return null != samlObject? samlObject.toString(): null;
    }

    @Override
    public List<String> getValues(final Object samlObject) {

        List<String> values = null;

        if (samlObject instanceof Attribute) {

            values = new ArrayList<>();
            for (final XMLObject childSamlObject : Attribute.class.cast(samlObject).getAttributeValues()) {

                values.add(this.getValue(childSamlObject));
            }
        }

        return values;
    }
}
