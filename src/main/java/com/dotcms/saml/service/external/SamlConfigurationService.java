package com.dotcms.saml.service.external;

/**
 * This service allows the interaction between some idp configuration and the properties itself.
 * It basically resolves the value or the default if the value does not exists.
 * @author jsanca
 */
public interface SamlConfigurationService {

    /**
     * Returns the configuration value for the {@link SamlName} as String
     * The configuration will look for in the identityProviderConfiguration the dotSamlName, if not found, will retrieve the default value.
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param samlName {@link SamlName}
     * @return String
     */
    String getConfigAsString(IdentityProviderConfiguration identityProviderConfiguration,   SamlName samlName);

    /**
     * Returns the configuration value for the {@link SamlName} as Boolean
     *  @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     *  @param samlName {@link SamlName}
     * @return Boolean
     */
    Boolean getConfigAsBoolean(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName);

    /**
     * Returns the configuration value for the {@link SamlName} as Array String
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param samlName {@link SamlName}
     * @return String array
     */
    String[] getConfigAsArrayString(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName);

    /**
     * Returns the configuration value for the {@link SamlName} as Integer
     * @param identityProviderConfiguration {@link IdentityProviderConfiguration}
     * @param samlName {@link SamlName}
     * @return Integer
     */
    Integer getConfigAsInteger(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName);
}
