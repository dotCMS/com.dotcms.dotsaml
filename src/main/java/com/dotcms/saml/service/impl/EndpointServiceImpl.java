package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.internal.EndpointService;
import com.dotcms.saml.service.external.IdentityProviderConfiguration;
import com.dotcms.saml.service.external.SamlConfigurationService;
import com.dotcms.saml.service.external.SamlName;
import com.dotcms.saml.service.external.SamlConstants;
import org.apache.commons.lang.StringUtils;

import java.net.MalformedURLException;

/**
 * Provides a helper for endpoint urls of the SAML config.
 * 
 * @author jsanca
 */
public class EndpointServiceImpl implements EndpointService {

	private final SamlConfigurationService samlConfigurationService;

	public EndpointServiceImpl(final SamlConfigurationService samlConfigurationService) {

		this.samlConfigurationService = samlConfigurationService;
	}

	/**
	 * In case the user wants some specific customer url, otherwise null. This
	 * URL is used on the metadata to fill out the AssertionConsumerService
	 * 
	 * @param identityProviderConfiguration IdpConfig
	 * @return String
	 */
	@Override
	public String getAssertionConsumerEndpoint(final IdentityProviderConfiguration identityProviderConfiguration) {

		// spEndpointHostname is a required field during edit.  Has to have value.
		return SamlConstants.HTTPS_SCHEMA
				+ spEndpointHostname(identityProviderConfiguration)
				+ SamlConstants.ASSERTION_CONSUMER_ENDPOINT_DOTSAML3SP
				+ "/"
				+ identityProviderConfiguration.getId();
	}

	/**
	 * In case the user wants some specific logout url, otherwise null. This URL
	 * is used on the metadata to fill out the assertion customer service
	 * 
	 * We are assuming that the issuerUrl which is posted by the Idp and 
	 * SingleLogoutEndpoint which is also posted by the Idp will be on the
	 * same domain and port.
	 * 
	 * @param identityProviderConfiguration IdpConfig
	 * @return String
	 */
	@Override
	public String getSingleLogoutEndpoint(final IdentityProviderConfiguration identityProviderConfiguration) {

		return SamlConstants.HTTPS_SCHEMA
				+ spEndpointHostname(identityProviderConfiguration)
				+ SamlConstants.LOGOUT_SERVICE_ENDPOINT_DOTSAML3SP
				+ "/"
				+ identityProviderConfiguration.getId();
	}

	/**
	 * Get's the access filter array, which are the exceptional cases to avoid
	 * to evaluate on the Saml Web Logic For instance if
	 * you include a file that shouldn't need any mapping, you can use it.
	 * 
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String []
	 */
	@Override
	public  String[] getAccessFilterArray(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String accessFilterValues = this.samlConfigurationService.getConfigAsString(
				identityProviderConfiguration, SamlName.DOT_SAML_ACCESS_FILTER_VALUES);

		return StringUtils.isNotBlank(accessFilterValues)?
				accessFilterValues.split( "," ) : null;
	}

	/**
	 * Returns the logout paths
	 * 
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String[]
	 */
	@Override
	public String[] getLogoutPathArray(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String logoutPathValues = this.samlConfigurationService.getConfigAsString(
				identityProviderConfiguration, SamlName.DOT_SAML_LOGOUT_PATH_VALUES);

		return StringUtils.isNotBlank(logoutPathValues)?
				logoutPathValues.split( "," ) : null;
	}

	/**
	 * Get's the include urls to be analyzed by the open saml plugin, usually
	 * the admin They can be a pattern
	 * 
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String []
	 */
	@Override
	public String[] getIncludePathArray(final IdentityProviderConfiguration identityProviderConfiguration) {

		final String accessFilterValues = this.samlConfigurationService.getConfigAsString(
				identityProviderConfiguration, SamlName.DOT_SAML_INCLUDE_PATH_VALUES);

		return StringUtils.isNotBlank( accessFilterValues) ?
				accessFilterValues.split( "," ) : null;
	}
	
	/*
	 * Utility to trim whitespace and remove the dash at the end if it exists.
	 */
	private static String spEndpointHostname(final IdentityProviderConfiguration identityProviderConfiguration) {

		String spHostName = identityProviderConfiguration.getSpEndpointHostname().trim();
		if (spHostName != null && spHostName.length() > 0 && spHostName.charAt(spHostName.length() - 1) == '/') {

			spHostName = spHostName.substring(0, spHostName.length() - 1);
		}
		 
		return spHostName;
	}
}
