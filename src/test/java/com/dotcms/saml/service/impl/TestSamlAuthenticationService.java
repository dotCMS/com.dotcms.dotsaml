package com.dotcms.saml.service.impl;

import com.dotcms.saml.SamlAuthenticationService;
import com.dotcms.saml.SamlServiceBuilder;
import org.junit.Assert;
import org.junit.Test;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;


public class TestSamlAuthenticationService {

    @Test
    public void testIsValidSamlRequest_TRUE () {

        final MockIdentityProviderConfigurationFactory idpFactory = new MockIdentityProviderConfigurationFactory();
        final SamlServiceBuilder samlServiceBuilder = new SamlServiceBuilderImpl();
        final SamlAuthenticationService samlAuthenticationService = samlServiceBuilder.buildAuthenticationService(
                idpFactory, new MockMessageObserver(), new MockSamlConfigurationService());
        final Map<String, String>  requestParamMap = new HashMap<>();
        final MockRequest  mockRequest             = new MockRequest();
        requestParamMap.put("SAMLResponse", "xxxxxxxx");
        mockRequest.addParameters(requestParamMap);

        Assert.assertTrue(samlAuthenticationService.isValidSamlRequest(mockRequest, null, idpFactory.findIdentityProviderConfigurationById("test.dotcms.com")));
    }

    @Test
    public void testIsValidSamlRequest_FALSE () {

        final MockIdentityProviderConfigurationFactory idpFactory = new MockIdentityProviderConfigurationFactory();
        final SamlServiceBuilder samlServiceBuilder = new SamlServiceBuilderImpl();
        final SamlAuthenticationService samlAuthenticationService = samlServiceBuilder.buildAuthenticationService(
                idpFactory, new MockMessageObserver(), new MockSamlConfigurationService());
        final MockRequest  mockRequest             = new MockRequest();

        Assert.assertFalse(samlAuthenticationService.isValidSamlRequest(mockRequest, null, idpFactory.findIdentityProviderConfigurationById("test.dotcms.com")));
    }

    @Test
    public void testRenderMetadataXML () {

        final MockIdentityProviderConfigurationFactory idpFactory = new MockIdentityProviderConfigurationFactory();
        final SamlServiceBuilder samlServiceBuilder = new SamlServiceBuilderImpl();
        final SamlAuthenticationService samlAuthenticationService = samlServiceBuilder.buildAuthenticationService(
                idpFactory, new MockMessageObserver(), new MockSamlConfigurationService());
        final StringWriter stringWriter            = new StringWriter();

        samlAuthenticationService.renderMetadataXML(stringWriter, idpFactory.findIdentityProviderConfigurationById("test.dotcms.com"));

        Assert.assertTrue(stringWriter.toString().length() > 0);
        Assert.assertTrue(stringWriter.toString().contains("EntityDescriptor"));
        Assert.assertTrue(stringWriter.toString().contains("entityID=\"https://test.com\""));
        Assert.assertTrue(stringWriter.toString().contains("X509Certificate"));
        Assert.assertTrue(stringWriter.toString().contains("EncryptionMethod"));
    }
}
