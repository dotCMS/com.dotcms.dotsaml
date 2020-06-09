package com.dotcms.saml.service;

import com.dotcms.saml.service.domain.SamlName;

public interface SamlConfigurationService {

    /**
     * Returns the configuration value for the {@link SamlName} as String
     * The configuration will look for in the identityProviderConfiguration the dotSamlName, if not found, will retrieve the default value.
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param dotSamlName {@link SamlName}
     * @return String
     */
    String getConfigAsString(IdentityProviderConfiguration identityProviderConfiguration,   SamlName dotSamlName);

    /**
     * Returns the configuration value for the {@link SamlName} as Boolean
     *  @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     *  @param dotSamlName {@link SamlName}
     * @return Boolean
     */
    Boolean getConfigAsBoolean(IdentityProviderConfiguration identityProviderConfiguration, SamlName dotSamlName);

    /**
     * Returns the configuration value for the {@link SamlName} as Array String
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param dotSamlName {@link SamlName}
     * @return String array
     */
    String[] getConfigAsArrayString(IdentityProviderConfiguration identityProviderConfiguration, SamlName dotSamlName);
}
