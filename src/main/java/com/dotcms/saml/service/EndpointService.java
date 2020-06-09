package com.dotcms.saml.service;

public interface EndpointService {
    String getAssertionConsumerEndpoint(IdentityProviderConfiguration identityProviderConfiguration);

    String getSingleLogoutEndpoint(IdentityProviderConfiguration identityProviderConfiguration);

    String[] getAccessFilterArray(IdentityProviderConfiguration identityProviderConfiguration);

    String[] getLogoutPathArray(IdentityProviderConfiguration identityProviderConfiguration);

    String[] getIncludePathArray(IdentityProviderConfiguration identityProviderConfiguration);
}
