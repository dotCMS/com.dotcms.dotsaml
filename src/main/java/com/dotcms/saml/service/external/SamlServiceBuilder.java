package com.dotcms.saml.service.external;

public interface SamlServiceBuilder {

    SamlAuthenticationService buildAuthenticationService (
            IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
            MessageObserver messageObserver,
            SamlConfigurationService samlConfigurationService);
}
