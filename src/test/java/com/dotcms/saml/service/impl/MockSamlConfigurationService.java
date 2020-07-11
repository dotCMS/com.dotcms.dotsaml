package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlName;
import com.dotcms.saml.service.external.SamlConstants;

import java.util.Map;
import java.util.function.Supplier;

public class MockSamlConfigurationService implements SamlConfigurationService {
    @Override
    public void initService(Map<String, Object> map) {

    }

    @Override
    public String getConfigAsString(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName) {

        switch (samlName) {

            case DOT_SAML_IDP_METADATA_PROTOCOL:
                return SamlConstants.DOT_SAML_IDP_METADATA_PROTOCOL_DEFAULT_VALUE;
            case DOTCMS_SAML_USE_ENCRYPTED_DESCRIPTOR:
                return "false";
        }
        return null;
    }

    @Override
    public String getConfigAsString(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName, Supplier<String> supplier) {
        return null;
    }

    @Override
    public Boolean getConfigAsBoolean(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName) {
        switch (samlName) {

            case DOTCMS_SAML_USE_ENCRYPTED_DESCRIPTOR:
                return false;
        }
        return false;
    }

    @Override
    public String[] getConfigAsArrayString(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName) {
        return new String[0];
    }

    @Override
    public Integer getConfigAsInteger(IdentityProviderConfiguration identityProviderConfiguration, SamlName samlName) {
        return null;
    }

    @Override
    public Map<String, String> createInitialMap() {
        return null;
    }
}
