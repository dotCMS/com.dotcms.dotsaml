package com.dotcms.saml.service.internal;

import com.dotcms.saml.service.external.IdentityProviderConfiguration;
import com.dotcms.saml.service.external.MetaData;
import org.opensaml.security.credential.Credential;

import java.util.Collection;

public interface MetaDataService {

    MetaData getMetaData(IdentityProviderConfiguration identityProviderConfiguration);

    MetaDescriptorService getMetaDescriptorService(IdentityProviderConfiguration identityProviderConfiguration);

    Collection<Credential> getSigningCredentials(IdentityProviderConfiguration identityProviderConfiguration);

    String getIdentityProviderDestinationSSOURL(IdentityProviderConfiguration identityProviderConfiguration);

    String getIdentityProviderDestinationSLOURL(IdentityProviderConfiguration identityProviderConfiguration);
}
