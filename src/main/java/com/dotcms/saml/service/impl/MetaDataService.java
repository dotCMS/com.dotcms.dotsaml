package com.dotcms.saml.service.impl;

import com.dotcms.plugin.saml.v3.meta.DefaultMetaDescriptorServiceImpl;
import com.dotcms.plugin.saml.v3.meta.MetaDescriptorService;
import com.dotcms.plugin.saml.v3.meta.MetadataBean;
import com.dotcms.plugin.saml.v3.parameters.DotsamlPropertiesService;
import com.dotcms.plugin.saml.v3.parameters.DotsamlPropertyName;
import com.dotcms.plugin.saml.v3.util.InstanceUtil;
import com.dotcms.repackage.org.apache.commons.io.IOUtils;
import com.dotcms.saml.service.IdentityProviderConfiguration;
import com.dotcms.saml.service.MetaDescriptorService;
import com.dotcms.saml.service.SamlConfigurationService;
import com.dotmarketing.util.Logger;
import org.opensaml.security.credential.Credential;

import java.io.FileInputStream;
import java.util.Collection;

/**
 * This service provides the encapsulation to interact with the SP and IDP metadata.
 * 
 * @author jsanca
 */
public class MetaDataService {

	private final SamlConfigurationService dotSamlConfigurationService;

	/**
	 * Gets the metadata, null if it can not be created.
	 * 
	 * @param idpConfig
	 *            IdpConfig
	 * @return MetadataBean
	 */
	public static MetadataBean getMetaData(IdpConfig idpConfig) {
		MetadataBean metadataBean = null;
		MetaDescriptorService descriptorParser = InstanceUtil.newInstance(
				DotsamlPropertiesService.getOptionString(idpConfig,
						DotsamlPropertyName.DOT_SAML_IDP_METADATA_PARSER_CLASS_NAME),
				DefaultMetaDescriptorServiceImpl.class);

		FileInputStream fileInputStream = null;

		try {
			fileInputStream = new FileInputStream(idpConfig.getIdPMetadataFile());

			metadataBean = descriptorParser.parse(fileInputStream, idpConfig);
		} catch (Exception exception) {
			Logger.error(MetaDataService.class, exception.getMessage(), exception);
		} finally {
			if (fileInputStream != null) {
				IOUtils.closeQuietly(fileInputStream);
			}
		}

		return metadataBean;
	}

	/**
	 * The meta descriptor service is created on the configuration, so we take
	 * advance and return the instance from it.
	 *
	 * @param idpConfig
	 *            IdpConfig
	 * @return MetaDescriptorService
	 */
	// Todo: this could be in the InstancePool
	public static MetaDescriptorService getMetaDescriptorService(IdpConfig idpConfig) {
		MetaDescriptorService metaDescriptorService = InstanceUtil.newInstance(
				DotsamlPropertiesService.getOptionString(idpConfig,
						DotsamlPropertyName.DOT_SAML_IDP_METADATA_PARSER_CLASS_NAME),
				DefaultMetaDescriptorServiceImpl.class);

		return metaDescriptorService;
	}

	public static Collection<Credential> getSigningCredentials(final IdentityProviderConfiguration idpConfig) {
		MetadataBean metadataBean = getMetaData(idpConfig);

		return (null != metadataBean) ? metadataBean.getCredentialSigningList() : null;
	}

	/**
	 * Gets the Identity Provider Destination Single Sign on URL
	 *
	 * @param idpConfig
	 *            IdpConfig
	 * @return String
	 */
	public String getIdentityProviderDestinationSSOURL(final IdentityProviderConfiguration idpConfig) {
		String url = null;
		String bindingType = DotsamlPropertiesService.getOptionString(idpConfig,
				DotsamlPropertyName.DOTCMS_SAML_BINDING_TYPE);
		MetadataBean metadataBean = getMetaData(idpConfig);

		if (null != metadataBean && null != metadataBean.getSingleSignOnBindingLocationMap()
				&& metadataBean.getSingleSignOnBindingLocationMap().containsKey(bindingType)) {
			url = metadataBean.getSingleSignOnBindingLocationMap().get(bindingType);
		}

		return url;
	}

	/**
	 * Gets the Identity Provider Destination Single Logout URL
	 *
	 * @param idpConfig
	 *            IdpConfig
	 * @return String
	 */
	public static String getIdentityProviderDestinationSLOURL(final IdentityProviderConfiguration identityProviderConfiguration) {
		String url = null;
		String bindingType = DotsamlPropertiesService.getOptionString(idpConfig,
				DotsamlPropertyName.DOTCMS_SAML_BINDING_TYPE);
		MetadataBean metadataBean = getMetaData(idpConfig);

		if (null != metadataBean && null != metadataBean.getSingleLogoutBindingLocationMap()
				&& metadataBean.getSingleLogoutBindingLocationMap().containsKey(bindingType)) {

			url = metadataBean.getSingleLogoutBindingLocationMap().get(bindingType);
		}

		return url;
	}
}
