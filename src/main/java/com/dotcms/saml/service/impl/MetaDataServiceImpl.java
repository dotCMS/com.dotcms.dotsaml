package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlName;
import com.dotcms.saml.service.internal.CredentialService;
import com.dotcms.saml.service.internal.EndpointService;
import com.dotcms.saml.service.internal.MetaDataService;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.external.MetaData;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.InstanceUtil;
import org.opensaml.security.credential.Credential;

import java.io.InputStream;
import java.nio.file.Files;
import java.util.Collection;

/**
 * This service provides the encapsulation to interact with the SP and IDP metadata.
 * 
 * @author jsanca
 */
public class MetaDataServiceImpl implements MetaDataService {

	private final SamlConfigurationService samlConfigurationService;
	private final MessageObserver          messageObserver;

	public MetaDataServiceImpl(final SamlConfigurationService samlConfigurationService,
							   final MessageObserver messageObserver) {

		this.samlConfigurationService = samlConfigurationService;
		this.messageObserver = messageObserver;
	}

	/**
	 * Gets the metadata, null if it can not be created.
	 * 
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return MetaDataBean
	 */
	@Override
	public MetaData getMetaData(final IdentityProviderConfiguration identityProviderConfiguration) {

		MetaData metadataBean = null;
		final MetaDescriptorService descriptorParser = InstanceUtil.newInstance(
				this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,
						SamlName.DOT_SAML_IDP_METADATA_PARSER_CLASS_NAME),
				()-> InstanceUtil.getInstance(MetaDescriptorService.class));

		try (InputStream inputStream = Files.newInputStream(identityProviderConfiguration.getIdPMetadataFile())) {

			metadataBean = descriptorParser.parse(inputStream, identityProviderConfiguration);
		} catch (Exception exception) {

			this.messageObserver.updateError(MetaDataServiceImpl.class, exception.getMessage(), exception);
		}

		return metadataBean;
	}

	/**
	 * The meta descriptor service is created on the configuration, so we take
	 * advance and return the instance from it.
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return MetaDescriptorService
	 */
	@Override
	public MetaDescriptorService getMetaDescriptorService(final IdentityProviderConfiguration identityProviderConfiguration) {

		final MetaDescriptorService metaDescriptorService = InstanceUtil.newInstance(
				this.samlConfigurationService.getConfigAsString(identityProviderConfiguration,
						SamlName.DOT_SAML_IDP_METADATA_PARSER_CLASS_NAME),
				DefaultMetaDescriptorServiceImpl.class);

		return metaDescriptorService;
	}

	@Override
	public Collection<Credential> getSigningCredentials(final IdentityProviderConfiguration identityProviderConfiguration) {

		final MetaData metadataBean = getMetaData(identityProviderConfiguration);

		return null != metadataBean? metadataBean.getCredentialSigningList() : null;
	}

	/**
	 * Gets the Identity Provider Destination Single Sign on URL
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getIdentityProviderDestinationSSOURL(final IdentityProviderConfiguration identityProviderConfiguration) {

		String url = null;
		final String bindingType = this.samlConfigurationService.getConfigAsString(
				identityProviderConfiguration, SamlName.DOTCMS_SAML_BINDING_TYPE);
		final MetaData metadataBean = getMetaData(identityProviderConfiguration);

		if (null != metadataBean && null != metadataBean.getSingleSignOnBindingLocationMap()
				&& metadataBean.getSingleSignOnBindingLocationMap().containsKey(bindingType)) {

			url = metadataBean.getSingleSignOnBindingLocationMap().get(bindingType);
		}

		return url;
	}

	/**
	 * Gets the Identity Provider Destination Single Logout URL
	 *
	 * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
	 * @return String
	 */
	@Override
	public String getIdentityProviderDestinationSLOURL(final IdentityProviderConfiguration identityProviderConfiguration) {

		String url = null;
		final String bindingType = this.samlConfigurationService.getConfigAsString(
				identityProviderConfiguration, SamlName.DOTCMS_SAML_BINDING_TYPE);
		final MetaData metadataBean = getMetaData(identityProviderConfiguration);

		if (null != metadataBean && null != metadataBean.getSingleLogoutBindingLocationMap()
				&& metadataBean.getSingleLogoutBindingLocationMap().containsKey(bindingType)) {

			url = metadataBean.getSingleLogoutBindingLocationMap().get(bindingType);
		}

		return url;
	}
}
