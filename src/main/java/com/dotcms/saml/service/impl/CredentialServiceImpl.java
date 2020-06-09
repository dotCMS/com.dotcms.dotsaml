package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.CredentialProvider;
import com.dotcms.saml.service.CredentialService;
import com.dotcms.saml.service.IdentityProviderConfiguration;
import com.dotcms.saml.service.SamlConfigurationService;
import com.dotcms.saml.service.domain.SamlName;
import com.dotcms.saml.utils.InstanceUtil;
import com.dotcms.saml.utils.SamlConstants;

public class CredentialServiceImpl implements CredentialService {

	private final SamlConfigurationService samlConfigurationService;

	public CredentialServiceImpl(final SamlConfigurationService samlConfigurationService) {

		this.samlConfigurationService = samlConfigurationService;
	}

	/**
	 * In case you need a custom credentials for the ID Provider (dotCMS)
	 * overrides the implementation class on the configuration. By default it
	 * uses the Idp metadata credentials info, from the XML to figure out this
	 * info.
	 *
	 * @param identityProviderConfiguration IdentityProviderConfiguration
	 * @return CredentialProvider
	 */
	@Override
	@SuppressWarnings( { "rawtypes", "unchecked" } )
	public CredentialProvider getIdProviderCustomCredentialProvider(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String className = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,
				SamlName.DOT_SAML_ID_PROVIDER_CUSTOM_CREDENTIAL_PROVIDER_CLASSNAME);
		final Class clazz      = InstanceUtil.getClass(className);

		return null != clazz? (CredentialProvider) InstanceUtil.newInstance(clazz) : null;
	}

	/**
	 * In case you need custom credentials for the Service Provider (DotCMS)
	 * overwrites the implementation class on the configuration. By default it
	 * uses a Trust Storage to get the keys and creates the credential.
	 * 
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return CredentialProvider
	 */
	@Override
	@SuppressWarnings( { "rawtypes", "unchecked" } )
	public  CredentialProvider getServiceProviderCustomCredentialProvider(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String className = this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,
				SamlName.DOT_SAML_SERVICE_PROVIDER_CUSTOM_CREDENTIAL_PROVIDER_CLASSNAME);
		final Class clazz      = InstanceUtil.getClass(className);

		return null != clazz? (CredentialProvider) InstanceUtil.newInstance(clazz) : null;
	}

	/**
	 * If the user wants to do a verifyAssertionSignature, by default true.
	 * There are some testing or diagnostic scenarios where you want to avoid
	 * the validation to identified issues, but in general on production this
	 * must be true.
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return boolean
	 */
	@Override
	public boolean isVerifyAssertionSignatureNeeded(final IdentityProviderConfiguration identityProviderConfiguration) {

		return identityProviderConfiguration.getSignatureValidationType().equals(SamlConstants.RESPONSE_AND_ASSERTION) ||
				identityProviderConfiguration.getSignatureValidationType().equals(SamlConstants.ASSERTION);
	}

	/**
	 * If the user wants to do a verifyResponseSignature, by default true.
	 * There are some testing or diagnostic scenarios where you want to avoid
	 * the validation to identified issues, but in general on production this
	 * must be true.
	 *
	 * @param identityProviderConfiguration identityProviderConfiguration
	 * @return boolean
	 */
	@Override
	public boolean isVerifyResponseSignatureNeeded(final IdentityProviderConfiguration identityProviderConfiguration) {

		return identityProviderConfiguration.getSignatureValidationType().equals( SamlConstants.RESPONSE_AND_ASSERTION ) ||
				identityProviderConfiguration.getSignatureValidationType().equals( SamlConstants.RESPONSE );
	}

	/**
	 * If the user wants to do a verifySignatureCredentials, by default true
	 * There are some testing or diagnostic scenarios where you want to avoid
	 * the validation to identified issues, but in general on production this
	 * must be true. Note: if isVerifyAssertionSignatureNeeded is true, this is
	 * also skipped.
	 * 
	 * @param identityProviderConfiguration IdentityProviderConfiguration
	 * @return boolean
	 */
	@Override
	public boolean isVerifySignatureCredentialsNeeded(final IdentityProviderConfiguration identityProviderConfiguration) {

		return this.samlConfigurationService.getConfigAsBoolean(identityProviderConfiguration, SamlName.DOT_SAML_VERIFY_SIGNATURE_CREDENTIALS);

	}

	/**
	 * If the user wants to do a verifySignatureProfile, by default true There
	 * are some testing or diagnostic scenarios where you want to avoid the
	 * validation to identified issues, but in general on production this must
	 * be true. Note: if isVerifyAssertionSignatureNeeded is true, this is also
	 * skipped.
	 * 
	 * @param identityProviderConfiguration IdentityProviderConfiguration
	 * @return boolean
	 */
	@Override
	public boolean isVerifySignatureProfileNeeded(final IdentityProviderConfiguration identityProviderConfiguration) {

		return this.samlConfigurationService.getConfigAsBoolean(identityProviderConfiguration, SamlName.DOT_SAML_VERIFY_SIGNATURE_PROFILE);
	}
}
