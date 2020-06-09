package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.CredentialProvider;
import com.dotcms.saml.service.CredentialService;
import com.dotcms.saml.service.EndpointService;
import com.dotcms.saml.service.IdentityProviderConfiguration;
import com.dotcms.saml.service.MessageObserver;
import com.dotcms.saml.service.SamlConfigurationService;
import com.dotcms.saml.service.SamlException;
import com.dotcms.saml.service.SamlService;
import com.dotcms.saml.service.domain.SamlName;
import com.dotcms.saml.utils.IdpConfigCredentialResolver;
import com.dotcms.saml.utils.SamlUtils;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This Service encapsulates all the Saml Stuff
 * 
 * @author jsanca
 */
public class SamlServiceImpl implements SamlService {

	private static final String DEFAULT_ELEMENT_NAME = "DEFAULT_ELEMENT_NAME";

	private static final XMLObjectBuilderFactory  builderFactory     = XMLObjectProviderRegistrySupport.getBuilderFactory();
	private static final Map<String, Credential>  credentialMap      = new ConcurrentHashMap<>();
	private static final Map<String, Credential>  idpCredentialMap   = new ConcurrentHashMap<>();

	private final CredentialService credentialService;
	private final EndpointService endpointService;
	private final MetaDataService metaDataService;
	private final MessageObserver messageObserver;
	private final SamlConfigurationService dotSamlConfigurationService;


	public SamlServiceImpl(final CredentialService credentialService,
						   final EndpointService endpointService,
						   final MetaDataService   metaDataService,
						   final MessageObserver   messageObserver,
						   final SamlConfigurationService dotSamlConfigurationService) {

		this.credentialService = credentialService;
		this.endpointService   = endpointService;
		this.metaDataService   = metaDataService;
		this.messageObserver   = messageObserver;
		this.dotSamlConfigurationService = dotSamlConfigurationService;
	}

	/**
	 * Build a SAML Object
	 * 
	 * @param clazz
	 * @param <T>
	 * @return T
	 */
	@Override
	@SuppressWarnings("unchecked")
	public <T> T buildSAMLObject(final Class<T> clazz) {

		T object = null;
		QName defaultElementName = null;

		try {
			defaultElementName = (QName) clazz.getDeclaredField(DEFAULT_ELEMENT_NAME).get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException | NoSuchFieldException e) {
			this.messageObserver.updateError(SamlServiceImpl.class, e.getMessage(), e);
			throw new IllegalArgumentException("Could not create SAML object: " + clazz);
		}

		return object;
	}

	/**
	 * Build the logout request based on the name id and session index.
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration} idp configuration for the logout request
	 * @param nameID {@link NameID} id
	 * @param sessionIndexValue {@link String} the session index value was saved when the user gets login
	 * @return LogoutRequest
	 */
	@Override
	public LogoutRequest buildLogoutRequest(final IdentityProviderConfiguration identityProviderConfiguration,
											final NameID nameID,
											final String sessionIndexValue) {

		final LogoutRequest logoutRequest        = buildSAMLObject(LogoutRequest.class);
		final String idpSingleLogoutDestionation = this.getIPDSLODestination(identityProviderConfiguration);
		SessionIndex sessionIndex 				 = null;

		// IDP logout url
		if (!StringUtils.isNotBlank(idpSingleLogoutDestionation)) {

			this.messageObserver.updateError(SamlServiceImpl.class,
					"The idpSingleLogoutDestination is not set in the IdP metadata or the configuration files");
			throw new SamlException("The property: "
					+ SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SLO_URL.getPropertyName()
					+ " must be set on the Site");
		}

		if (null == nameID || StringUtils.isBlank(sessionIndexValue)) {

			this.messageObserver.updateError(SamlServiceImpl.class, "The nameID or sessionIndex are null");
			throw new SamlException("The nameID or sessionIndex are null");
		}

		logoutRequest.setIssueInstant(new DateTime());
		logoutRequest.setID(SamlUtils.generateSecureRandomId());

		this.messageObserver.updateDebug(SamlServiceImpl.class,
				"Creating the logout request for NameID: " + nameID + ", SessionIndex: " + sessionIndexValue);

		// id for the sender
		logoutRequest.setDestination(idpSingleLogoutDestionation);
		logoutRequest.setIssuer(this.buildIssuer(identityProviderConfiguration));

		final NameID newNameID = this.buildSAMLObject(NameID.class);
		newNameID.setValue(nameID.getValue());
		newNameID.setFormat(nameID.getFormat());
		logoutRequest.setNameID(newNameID);

		sessionIndex = this.buildSAMLObject(SessionIndex.class);
		sessionIndex.setSessionIndex(sessionIndexValue);
		logoutRequest.getSessionIndexes().add(sessionIndex);

		logoutRequest.setReason(SINGLE_LOGOUT_REASON);
		logoutRequest.setVersion(SAMLVersion.VERSION_20);

		return logoutRequest;
	}

	/**
	 * Return the value of the /AuthnStatement@SessionIndex element in an
	 * assertion
	 *
	 * @return The value. <code>null</code>, if the assertion does not contain
	 *         the element.
	 */
	@Override
	public String getSessionIndex(final Assertion assertion) {
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

	/**
	 * Build an authentication request.
	 * @param request {@link HttpServletRequest}
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return AuthnRequest
	 */
	@Override
	public AuthnRequest buildAuthnRequest(final HttpServletRequest request,
										  final IdentityProviderConfiguration identityProviderConfiguration) {

		final String ipDSSODestination  = this.getIPDSSODestination(identityProviderConfiguration);

		// IDP url
		if (StringUtils.isBlank(ipDSSODestination)) {

			this.messageObserver.updateError(SamlServiceImpl.class,
					"The ipDSSODestination is not set in the idp metadata, neither the configuration files");
			throw new SamlException("The property: "
					+ SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SSO_URL.getPropertyName()
					+ " must be set on the host");
		}

		final AuthnRequest authnRequest = this.buildSAMLObject(AuthnRequest.class);

		// this ensure that the message redirected is not too old
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(ipDSSODestination);

		// Get the protocol from the user, or use a default one:
		// SAMLConstants.SAML2_ARTIFACT_BINDING_URI
		authnRequest.setProtocolBinding(
				this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration, SamlName.DOTCMS_SAML_PROTOCOL_BINDING));

		// this is the address that receives the SAML Assertion, after a
		// successful authentication on the IdP.
		authnRequest.setAssertionConsumerServiceURL(this.getAssertionConsumerEndpoint(request, identityProviderConfiguration));

		// this is a uid or random id just to identified the response.
		authnRequest.setID(SamlUtils.generateSecureRandomId());

		// id for the sender
		authnRequest.setIssuer(this.buildIssuer(identityProviderConfiguration));

		authnRequest.setNameIDPolicy(this.buildNameIdPolicy(identityProviderConfiguration));
		authnRequest.setRequestedAuthnContext(this.buildRequestedAuthnContext(identityProviderConfiguration));
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setForceAuthn(
				this.dotSamlConfigurationService.getConfigAsBoolean(identityProviderConfiguration, SamlName.DOTCMS_SAML_FORCE_AUTHN));

		return authnRequest;
	}

	/**
	 * Gets from the destination sso url from the configuration.
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getIPDSSODestination(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String redirectIdentityProviderDestinationSSOURL = this.metaDataService
				.getIdentityProviderDestinationSSOURL(identityProviderConfiguration);

		// first check the meta data info., secondly the idpConfig
		return (null != redirectIdentityProviderDestinationSSOURL) ? redirectIdentityProviderDestinationSSOURL
				: this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration,
						SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SSO_URL);
	}

	/**
	 * Gets from the destination slo url from the configuration
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getIPDSLODestination(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String redirectIdentityProviderDestinationSLOURL = this.metaDataService
				.getIdentityProviderDestinationSLOURL(identityProviderConfiguration);

		// first check the meta data info., secondly the idpConfig
		return (null != redirectIdentityProviderDestinationSLOURL) ?
				redirectIdentityProviderDestinationSLOURL
				: this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration,
						SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SLO_URL);
	}

	/**
	 * Get the assertion consumer endpoint from the configuration.
	 * @param request {@link HttpServletRequest}
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getAssertionConsumerEndpoint(final HttpServletRequest request,
											   final IdentityProviderConfiguration identityProviderConfiguration) {

		final String assertionConsumerEndpoint = this.endpointService.
				getAssertionConsumerEndpoint(identityProviderConfiguration);

		// this is the same original request. Consequently where should be
		// redirected when the authentication is done.
		final StringBuilder builder = new StringBuilder(request.getRequestURI());

		if (null != request.getQueryString()) {
			builder.append('?').append(request.getQueryString());
		}

		return null != assertionConsumerEndpoint ? assertionConsumerEndpoint : builder.toString();
	}


	/**
	 * Build the Id for the sender.
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return Issuer
	 */
	@Override
	public Issuer buildIssuer(final IdentityProviderConfiguration identityProviderConfiguration) {

		final Issuer issuer = this.buildSAMLObject(Issuer.class);

		issuer.setValue(getSPIssuerValue(identityProviderConfiguration));

		return issuer;
	}

	/**
	 * Get the id for the Issuer, it is the SP identifier on the IdP
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getSPIssuerValue(final IdentityProviderConfiguration identityProviderConfiguration) {
		// spIssuerURL is a required field. It should have value.
		return identityProviderConfiguration.getSpIssuerURL();
	}

	/**
	 * Return the policy for the Name ID (which is the IdP identifier for the
	 * user)
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return NameIDPolicy
	 */
	@Override
	public NameIDPolicy buildNameIdPolicy(final IdentityProviderConfiguration identityProviderConfiguration) {

		final NameIDPolicy nameIDPolicy = this.buildSAMLObject(NameIDPolicy.class);

		// True if you want that when the user does not exists, allows to create
		nameIDPolicy.setAllowCreate(this.dotSamlConfigurationService.getConfigAsBoolean(identityProviderConfiguration,
				SamlName.DOTCMS_SAML_POLICY_ALLOW_CREATE));

		// todo: should set the SPNameQualifier

		// it supports several formats, such as Kerberos, email, Windows Domain
		// Qualified Name, etc.
		// “The transient identifier is a random identifier that does not have
		// any connection to the user.
		// A transient identifier will be different for every time the user
		// signs in.”
		nameIDPolicy.setFormat(this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration,
				SamlName.DOTCMS_SAML_NAME_ID_POLICY_FORMAT));

		return nameIDPolicy;
	}

	/**
	 * Build the Authentication context, with the login and password strategies
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return RequestedAuthnContext
	 */
	@Override
	public  RequestedAuthnContext buildRequestedAuthnContext(final IdentityProviderConfiguration identityProviderConfiguration) {

		final RequestedAuthnContext requestedAuthnContext = this.buildSAMLObject(RequestedAuthnContext.class);

		requestedAuthnContext.setComparison(this.getAuthnContextComparisonTypeEnumeration(identityProviderConfiguration));

		final AuthnContextClassRef passwordAuthnContextClassRef = this.buildSAMLObject(AuthnContextClassRef.class);

		passwordAuthnContextClassRef.setAuthnContextClassRef(this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration,
				SamlName.DOTCMS_SAML_AUTHN_CONTEXT_CLASS_REF));

		requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

		return requestedAuthnContext;
	}

	/**
	 * Based on the configuration properties get the desire comparison type
	 *
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 * @return AuthnContextComparisonTypeEnumeration
	 */
	@Override
	public AuthnContextComparisonTypeEnumeration getAuthnContextComparisonTypeEnumeration(
			final IdentityProviderConfiguration identityProviderConfiguration) {

		AuthnContextComparisonTypeEnumeration comparisonTypeEnumeration = AuthnContextComparisonTypeEnumeration.MINIMUM;

		final String enumName = this.dotSamlConfigurationService.getConfigAsString(identityProviderConfiguration,
				SamlName.DOTCMS_SAML_AUTHN_COMPARISON_TYPE);

		if (StringUtils.isNotBlank(enumName)) {

			if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(enumName)) {

				comparisonTypeEnumeration = AuthnContextComparisonTypeEnumeration.BETTER;
			} else if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(enumName)) {

				comparisonTypeEnumeration = AuthnContextComparisonTypeEnumeration.EXACT;
			} else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(enumName)) {

				comparisonTypeEnumeration = AuthnContextComparisonTypeEnumeration.MAXIMUM;
			}
			// MINIMUN is not necessary since it is the default one.
		}

		return comparisonTypeEnumeration;
	}

	/**
	 * Get the Logout Identity Provider Destination
	 *
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 * @return Endpoint
	 */
	@Override
	public Endpoint getIdentityProviderSLODestinationEndpoint(final IdentityProviderConfiguration identityProviderConfiguration) {

		final SingleLogoutService endpoint = this.buildSAMLObject(SingleLogoutService.class);

		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(this.getIPDSLODestination(identityProviderConfiguration));

		return endpoint;
	}

	/**
	 * Get the Identity Provider Destination
	 *
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 * @return Endpoint
	 */
	@Override
	public Endpoint getIdentityProviderDestinationEndpoint(final IdentityProviderConfiguration identityProviderConfiguration) {

		final SingleSignOnService endpoint = this.buildSAMLObject(SingleSignOnService.class);

		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(this.getIPDSSODestination(identityProviderConfiguration));

		return endpoint;
	}

	/**
	 * Get the Assertion decrypted
	 *
	 * @param artifactResponse {@link ArtifactResponse}
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 * @return Assertion
	 */
	@Override
	public Assertion getAssertion(final ArtifactResponse artifactResponse,
								  final IdentityProviderConfiguration identityProviderConfiguration) {

		final EncryptedAssertion encryptedAssertion =
				this.getEncryptedAssertion(artifactResponse);
		/// this is the user message itself
		final Assertion assertion = this.decryptAssertion(
				encryptedAssertion, identityProviderConfiguration);

		return assertion;
	}

	/**
	 * Get the Assertion decrypted
	 *
	 * @param response {@link Response}
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 *
	 * @return Assertion
	 */
	@Override
	public Assertion getAssertion(final Response response,
								  final IdentityProviderConfiguration identityProviderConfiguration) {

		final EncryptedAssertion encryptedAssertion;
		Assertion assertion = null;

		if (this.dotSamlConfigurationService.getConfigAsBoolean(identityProviderConfiguration,
				SamlName.DOTCMS_SAML_IS_ASSERTION_ENCRYPTED)) {

			encryptedAssertion = response.getEncryptedAssertions().get(0);
			/// this is the user message itself
			assertion = this.decryptAssertion(encryptedAssertion, identityProviderConfiguration);
		} else {

			assertion = response.getAssertions().get(0);
		}

		return assertion;
	}

	/**
	 * Just get the Encrypted assertion from the {@link ArtifactResponse}
	 *
	 * @param artifactResponse {@link ArtifactResponse}
	 * @return EncryptedAssertion
	 */
	@Override
	public EncryptedAssertion getEncryptedAssertion(final ArtifactResponse artifactResponse) {

		final Response response = (Response) artifactResponse.getMessage();
		return response.getEncryptedAssertions().get(0);
	}

	/**
	 * Decrypt an {@link EncryptedAssertion}
	 *
	 * @param encryptedAssertion {@link EncryptedAssertion}
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 * @return Assertion
	 */
	@Override
	public Assertion decryptAssertion(final EncryptedAssertion encryptedAssertion,
									  final IdentityProviderConfiguration identityProviderConfiguration) {

		Assertion assertion = null;
		final StaticKeyInfoCredentialResolver keyInfoCredentialResolver =
				new StaticKeyInfoCredentialResolver(this.getCredential(identityProviderConfiguration));

		final Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

		try {

			decrypter.setRootInNewDocument(true);
			assertion = decrypter.decrypt(encryptedAssertion);
		} catch (DecryptionException e) {

			this.messageObserver.updateError(SamlServiceImpl.class, e.getMessage(), e);
			throw new SamlException(e.getMessage(), e);
		}

		return assertion;
	}

	private void validateSignature(final Assertion assertion, final Collection<Credential> credentials)
			throws SignatureException {
		
		for (final Credential credential : credentials) {
			try {

				SignatureValidator.validate(assertion.getSignature(), credential);

				return;
			} catch (SignatureException ignore) {

				this.messageObserver.updateInfo(SamlServiceImpl.class, "Signature Validation failed with provided credential (ignore?): " +
						ignore.getMessage());
			}
		}

		this.messageObserver.updateInfo(SamlServiceImpl.class, "Couldn't find any valid credential to validate the assertion signature");
		throw new SignatureException("Assertion Signature cannot be validated");
	}

	private void validateSignature(final Response response, final Collection<Credential> credentials)
			throws SignatureException {

		this.messageObserver.updateDebug(SamlServiceImpl.class,
				"Validating Signature - Credentials " + ((credentials != null) ? "are present" : "are null"));
		this.messageObserver.updateDebug(SamlServiceImpl.class,
				"Validating Signature - Credentials " + ((response != null) ? "are present" : "are null"));

		for (final Credential credential : credentials) {

			try {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Validating Signature - Credential " +
						((credential != null) ? "is present" : "is null"));
				this.messageObserver.updateDebug(SamlServiceImpl.class, "Validating Signature - response.getSignature " +
						((response.getSignature() != null)?"is present" : "is null"));

				SignatureValidator.validate(response.getSignature(), credential);
				return;
			} catch (SignatureException ignore) {

				this.messageObserver.updateInfo(SamlServiceImpl.class,
						"Signature Validation failed with provided credential(s): " + ignore.getMessage());
			}
		}

		this.messageObserver.updateInfo(SamlServiceImpl.class, "Couldn't find any valid credential to validate the response signature");
		throw new SignatureException("Response Signature cannot be validated");
	}

	/**
	 * Does the verification of the assertion
	 *
	 * @param assertion {@link Assertion}
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 */
	@Override
	public void verifyAssertionSignature(final Assertion assertion,
										 final IdentityProviderConfiguration identityProviderConfiguration) {

		if (this.credentialService.isVerifyAssertionSignatureNeeded(identityProviderConfiguration) != assertion.isSigned()) {

			this.messageObserver.updateError(SamlServiceImpl.class, "Assertion Signatures for IdP '" +
					identityProviderConfiguration.getIdpName() + "' do not match.");
			throw new SamlException("The SAML Assertion for IdP '" +
					identityProviderConfiguration.getIdpName() + "' does not match");
		}

		// If unsigned, No need to go further.
		if (!this.credentialService.isVerifyAssertionSignatureNeeded(identityProviderConfiguration)) {

			this.messageObserver.updateError(SamlServiceImpl.class, "The verification assertion signature and status code for IdP '" +
					identityProviderConfiguration.getIdpName() + "' was skipped.");
			return; // Exit
		}

		// Here on out we are checking signature
		try {

			if (this.credentialService.isVerifySignatureProfileNeeded(identityProviderConfiguration)) {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Executing Profile Validation...");

				new SAMLSignatureProfileValidator().validate(assertion.getSignature());

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Profile Validation finished");
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Skipping the Verify Signature Profile check");
			}

			// Ask on the config if the app wants signature validator
			if (this.credentialService.isVerifySignatureCredentialsNeeded(identityProviderConfiguration)) {

				if (null != this.metaDataService.getSigningCredentials(identityProviderConfiguration)) {

					this.messageObserver.updateDebug(SamlServiceImpl.class,
							"Validating the signatures: " + this.metaDataService.getSigningCredentials(identityProviderConfiguration));

					this.validateSignature(assertion, this.metaDataService.getSigningCredentials(identityProviderConfiguration));

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Executing signatures validation...");
				} else {

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Validating the signature with a IdP Credentials...");

					SignatureValidator.validate(assertion.getSignature(), getIdPCredentials(identityProviderConfiguration));

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Validation of the signature with a IdP Credentials finished");
				}
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Skipping the Verify Signature Profile check");
			}

			this.messageObserver.updateDebug(SamlServiceImpl.class, "SAML Assertion signature verified");

		} catch (SignatureException e) {

			this.messageObserver.updateError(SamlServiceImpl.class, e.getMessage(), e);
			throw new SamlException(e.getMessage(), e);
		}
	}

	/**
	 * Does the verification of the assertion
	 *
	 * @param response {@link Assertion}
	 * @param identityProviderConfiguration  {@link IdentityProviderConfiguration}
	 */
	@Override
	public  void verifyResponseSignature(final Response response, final IdentityProviderConfiguration identityProviderConfiguration) {

		// The check signature in dotCMS and IdP must match
		if (this.credentialService.isVerifyResponseSignatureNeeded(identityProviderConfiguration) != response.isSigned()) {

			this.messageObserver.updateError(SamlServiceImpl.class, "The response signatures for IdP '" + identityProviderConfiguration.getIdpName() + "' do not match.");
			throw new SamlException("The SAML Response for IdP '" + identityProviderConfiguration.getIdpName() + "' does not match");
		}

		// If unsigned, No need to go further.
		if (!this.credentialService.isVerifyResponseSignatureNeeded(identityProviderConfiguration)) {

			this.messageObserver.updateDebug(SamlServiceImpl.class, "The verification response signature and status code for IdP '" +
					identityProviderConfiguration.getIdpName() + "' was skipped.");
			return; // Exit
		}

		// Here on out we are checking signature
		try {
			if (this.credentialService.isVerifySignatureProfileNeeded(identityProviderConfiguration)) {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Executing Profile Validation...");

				new SAMLSignatureProfileValidator().validate(response.getSignature());

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Profile Validation finished");
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Skipping verification of Signature Profile");
			}

			// Ask on the config if the app wants signature validator
			if (this.credentialService.isVerifySignatureCredentialsNeeded(identityProviderConfiguration)) {

				if (null != this.metaDataService.getSigningCredentials(identityProviderConfiguration)) {

					this.messageObserver.updateDebug(SamlServiceImpl.class,
							"Validating the signatures: " + this.metaDataService.getSigningCredentials(identityProviderConfiguration));

					this.validateSignature(response, MetaDataService.getSigningCredentials(identityProviderConfiguration));

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Executing signature validation...");
				} else {

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Validating the signature with a IdP Credentials...");

					SignatureValidator.validate(response.getSignature(), this.getIdPCredentials(identityProviderConfiguration));

					this.messageObserver.updateDebug(SamlServiceImpl.class, "Validation of the signature with a IdP Credentials finished");
				}
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Skipping the Verify Signature Profile check");
			}

			this.messageObserver.updateDebug(SamlServiceImpl.class, "SAML Response signature verified");

		} catch (SignatureException e) {

			this.messageObserver.updateError(SamlServiceImpl.class, e.getMessage(), e);
			throw new SamlException(e.getMessage(), e);
		}
	}

	/**
	 * Creates the credential based on the configuration
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return Credential
	 */
	@Override
	public  Credential createCredential(final IdentityProviderConfiguration identityProviderConfiguration) {

		final Criterion   criterion;
		final CriteriaSet criteriaSet;
		final CredentialProvider customCredentialProvider = this.credentialService
				.getServiceProviderCustomCredentialProvider(identityProviderConfiguration);
		Credential credential = null;

		try {

			if (null != customCredentialProvider) {

				credential = customCredentialProvider.createCredential();
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class,
						"Creating credentials for IdP: " + identityProviderConfiguration.getIdpName());

				final IdpConfigCredentialResolver resolver = new IdpConfigCredentialResolver();

				criterion   = new EntityIdCriterion(identityProviderConfiguration.getId());
				criteriaSet = new CriteriaSet();
				criteriaSet.add(criterion);
				credential = resolver.resolveSingle(criteriaSet);

				this.messageObserver.updateDebug(SamlServiceImpl.class,
						"Credentials have been created: " + credential);
			}
		} catch (ResolverException e) {

			final String errorMsg ="An error occurred when reading credentials: " + e.getMessage();
			this.messageObserver.updateError(SamlServiceImpl.class, errorMsg, e);
			throw new SamlException(errorMsg, e);
		}

		return credential;
	}

	/**
	 * Get the SP credential
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return Credential
	 */
	@Override
	public Credential getCredential(final IdentityProviderConfiguration identityProviderConfiguration) {

		if (!credentialMap.containsKey(identityProviderConfiguration.getSpEndpointHostname())) {

			final Credential credential = this.createCredential(identityProviderConfiguration);

			if (null != credential) {

				credentialMap.put(identityProviderConfiguration.getSpEndpointHostname(), credential);
			} else {

				this.messageObserver.updateError(SamlServiceImpl.class,
						"Credential is null for site: " + identityProviderConfiguration.getSpEndpointHostname());

				throw new SamlException("Credential is null for site: " + identityProviderConfiguration.getSpEndpointHostname());
			}
		}

		return credentialMap.get(identityProviderConfiguration.getSpEndpointHostname());
	}

	private Credential createIdpCredential(final IdentityProviderConfiguration identityProviderConfiguration) {

		KeyPair keyPair          = null;
		Credential idpCredential = null;
		final CredentialProvider customCredentialProvider = this.credentialService
				.getIdProviderCustomCredentialProvider(identityProviderConfiguration);

		try {

			this.messageObserver.updateDebug(SamlServiceImpl.class, "Creating credential for IdP '" +
					identityProviderConfiguration.getIdpName() + "'");

			if (null != customCredentialProvider) {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Using custom credential provider");
				idpCredential = customCredentialProvider.createCredential();
			} else {

				this.messageObserver.updateDebug(SamlServiceImpl.class, "Using standard credential algorithm");
				// this fallback generates just a random keypair not very useful
				// to validate the signature.
				keyPair       = KeySupport.generateKeyPair("RSA", 1024, null);
				idpCredential = CredentialSupport.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {

			final String errorMsg = "An error occurred when generating credential for IdP '" + identityProviderConfiguration.getIdpName() +
					"': " + e.getMessage();
			this.messageObserver.updateError(SamlServiceImpl.class, errorMsg, e);
			throw new SamlException(errorMsg, e);
		}

		return idpCredential;
	}

	@Override
	public Credential getIdPCredentials(final IdentityProviderConfiguration identityProviderConfiguration) {

		if (!idpCredentialMap.containsKey(identityProviderConfiguration)) {

			idpCredentialMap.put(identityProviderConfiguration.getSpEndpointHostname(), this.createIdpCredential(identityProviderConfiguration));
		}

		return idpCredentialMap.get(identityProviderConfiguration.getSpEndpointHostname());
	}
}
