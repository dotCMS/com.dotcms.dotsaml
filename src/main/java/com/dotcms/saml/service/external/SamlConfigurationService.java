package com.dotcms.saml.service.external;

import com.google.common.collect.ImmutableMap;
import org.opensaml.saml.saml2.core.AuthnContext;

import java.util.Map;

/**
 * This service allows the interaction between some idp configuration and the properties itself.
 * It basically resolves the value or the default if the value does not exists.
 * @author jsanca
 */
public interface SamlConfigurationService {

    /**
     * Init the service
     * @param context {@link Map}
     */
    void initService (Map<String, Object> context);

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

    /**
     * Provides the initial values for a configuration map
     * @return Map
     */
    default Map<String, String>  createInitialMap() {

        return new ImmutableMap.Builder<String, String>()
                .put(SamlName.DOTCMS_SAML_AUTHN_CONTEXT_CLASS_REF.getPropertyName(), AuthnContext.PASSWORD_AUTHN_CTX)
                .put(SamlName.DOTCMS_SAML_BINDING_TYPE.getPropertyName(),            BindingType.REDIRECT.getBinding())
                // todo: continue here with the defaults
                .build();
    }
}
