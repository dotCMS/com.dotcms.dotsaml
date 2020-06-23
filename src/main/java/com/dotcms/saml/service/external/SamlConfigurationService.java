package com.dotcms.saml.service.external;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.NameIDType;

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
                .put(SamlName.DOT_SAML_ACCESS_FILTER_VALUES.getPropertyName(),          null)
                .put(SamlName.DOTCMS_SAML_AUTHN_COMPARISON_TYPE.getPropertyName(),      null)
                .put(SamlName.DOTCMS_SAML_AUTHN_CONTEXT_CLASS_REF.getPropertyName(),    AuthnContext.PASSWORD_AUTHN_CTX)
                .put(SamlName.DOTCMS_SAML_BINDING_TYPE.getPropertyName(),               BindingType.REDIRECT.getBinding())
                .put(SamlName.DOTCMS_SAML_BUILD_ROLES.getPropertyName(),                SamlConstants.DOTCMS_SAML_BUILD_ROLES_ALL_VALUE)
                .put(SamlName.DOT_SAML_CLOCK_SKEW.getPropertyName(),                    "10000")
                .put(SamlName.DOT_SAML_EMAIL_ATTRIBUTE.getPropertyName(),               "mail")
                .put(SamlName.DOT_SAML_EMAIL_ATTRIBUTE_ALLOW_NULL.getPropertyName(),    "true")
                .put(SamlName.DOT_SAML_FIRSTNAME_ATTRIBUTE.getPropertyName(),           "givenName")
                .put(SamlName.DOT_SAML_FIRSTNAME_ATTRIBUTE_NULL_VALUE.getPropertyName(), null)
                .put(SamlName.DOT_SAML_LASTNAME_ATTRIBUTE.getPropertyName(),             "sn")
                .put(SamlName.DOT_SAML_LASTNAME_ATTRIBUTE_NULL_VALUE.getPropertyName(),  null)
                .put(SamlName.DOT_SAML_ROLES_ATTRIBUTE.getPropertyName(),                "authorizations")
                .put(SamlName.DOTCMS_SAML_IS_LOGOUT_NEED.getPropertyName(),              "true")
                .put(SamlName.DOT_SAML_LOGOUT_SERVICE_ENDPOINT_URL.getPropertyName(),    null)
                .put(SamlName.DOT_SAML_IDP_METADATA_PARSER_CLASS_NAME.getPropertyName(), null)
                .put(SamlName.DOT_SAML_IDP_METADATA_PROTOCOL.getPropertyName(),          SamlConstants.DOT_SAML_IDP_METADATA_PROTOCOL_DEFAULT_VALUE)
                .put(SamlName.DOTCMS_SAML_IS_ASSERTION_ENCRYPTED.getPropertyName(),      "false")
                .put(SamlName.DOT_SAML_MESSAGE_LIFE_TIME.getPropertyName(),              "20000")
                .put(SamlName.DOTCMS_SAML_FORCE_AUTHN.getPropertyName(),                 "false")
                .put(SamlName.DOTCMS_SAML_OPTIONAL_USER_ROLE.getPropertyName(),          null)
                .put(SamlName.DOTCMS_SAML_POLICY_ALLOW_CREATE.getPropertyName(),         "false")
                .put(SamlName.DOT_SAML_INCLUDE_PATH_VALUES.getPropertyName(),            SamlConstants.DOT_SAML_INCLUDE_PATH_DEFAULT_VALUES)
                .put(SamlName.DOT_SAML_LOGOUT_PATH_VALUES.getPropertyName(),             SamlConstants.DOT_SAML_LOGOUT_PATH_DEFAULT_VALUES)
                .put(SamlName.DOTCMS_SAML_NAME_ID_POLICY_FORMAT.getPropertyName(),       NameIDType.PERSISTENT)
                .put(SamlName.DOTCMS_SAML_PROTOCOL_BINDING.getPropertyName(),            SAMLConstants.SAML2_REDIRECT_BINDING_URI)
                .put(SamlName.DOT_SAML_REMOVE_ROLES_PREFIX.getPropertyName(),            StringUtils.EMPTY)
                .put(SamlName.DOTCMS_SAML_USE_ENCRYPTED_DESCRIPTOR.getPropertyName(),    "false")
                .put(SamlName.DOT_SAML_VERIFY_SIGNATURE_CREDENTIALS.getPropertyName(),   "true")
                .put(SamlName.DOT_SAML_VERIFY_SIGNATURE_PROFILE.getPropertyName(),       "true")
                .put(SamlName.DOTCMS_SAML_CLEAR_LOCATION_QUERY_PARAMS.getPropertyName(), "true")
                .put(SamlName.DOTCMS_SAML_LOGIN_UPDATE_EMAIL.getPropertyName(),          "true")
                .put(SamlName.DOT_SAML_ALLOW_USER_SYNCHRONIZATION.getPropertyName(),     "true")
                .put(SamlName.DOT_SAML_SERVICE_PROVIDER_CUSTOM_CREDENTIAL_PROVIDER_CLASSNAME.getPropertyName(), null)
                .put(SamlName.DOTCMS_SAML_OPTIONAL_USER_ROLE.getPropertyName(),                                 null)
                .put(SamlName.DOTCMS_SAML_INCLUDE_ROLES_PATTERN.getPropertyName(),                              null)
                .put(SamlName.DOTCMS_SAML_ASSERTION_RESOLVER_HANDLER_CLASS_NAME.getPropertyName(),              null)
                .put(SamlName.DOT_SAML_ID_PROVIDER_CUSTOM_CREDENTIAL_PROVIDER_CLASSNAME.getPropertyName(),      null)
                .put(SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SLO_URL.getPropertyName(),              null)
                .put(SamlName.DOTCMS_SAML_IDENTITY_PROVIDER_DESTINATION_SSO_URL.getPropertyName(),              null)
                .build();
    }
}
