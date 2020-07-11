package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.IdentityProviderConfigurationFactory;

import java.security.KeyPair;
import java.security.cert.Certificate;

public class MockIdentityProviderConfigurationFactory implements IdentityProviderConfigurationFactory {

    private static final KeyPair KEY_PAIR        = MockSecurityUtils.generateKeyPair();
    private static final Certificate CERTIFICATE = MockSecurityUtils.generateCertificate(KEY_PAIR);

    @Override
    public IdentityProviderConfiguration findIdentityProviderConfigurationById(String s) {
        return new IdentityProviderConfiguration() {
            @Override
            public boolean isEnabled() {
                return true;
            }

            @Override
            public String getSpIssuerURL() {
                return "https://test.com";
            }

            @Override
            public String getIdpName() {
                return "test.com/sp";
            }

            @Override
            public String getId() {
                return "123";
            }

            @Override
            public String getSpEndpointHostname() {
                return "https://test.com";
            }

            @Override
            public String getSignatureValidationType() {
                return "signature";
            }

            @Override
            public char[] getIdPMetadataFile() {
                return new char[0];
            }

            @Override
            public char[] getPublicCert() {
                try {

                    return MockSecurityUtils.formatCrtFileContents(CERTIFICATE).toCharArray();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public char[] getPrivateKey() {
                return MockSecurityUtils.generatePrivateKeyAsString(KEY_PAIR).toCharArray();
            }

            @Override
            public Object getOptionalProperty(String s) {
                return null;
            }

            @Override
            public boolean containsOptionalProperty(String s) {
                return false;
            }
        };
    }
}
