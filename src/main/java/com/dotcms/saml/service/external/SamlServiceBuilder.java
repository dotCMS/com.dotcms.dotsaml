package com.dotcms.saml.service.external;

/**
 * This service builds the service to be reference on the bundle context of OSGI
 * @author jsanca
 */
public interface SamlServiceBuilder {

    /**
     * Creates the Saml Authentication Facade for the SAML integration
     * @param identityProviderConfigurationFactory {@link IdentityProviderConfigurationFactory}
     * @param messageObserver {@link MessageObserver}
     * @param samlConfigurationService {@link SamlConfigurationService}
     * @return SamlAuthenticationService
     */
    SamlAuthenticationService buildAuthenticationService (
            IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
            MessageObserver messageObserver,
            SamlConfigurationService samlConfigurationService);
}
