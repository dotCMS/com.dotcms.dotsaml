package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfiguration;
import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.InstanceUtil;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;

public class TestSamlCoreService {

    @Test
    public void testBuildSAMLObject() {

        final MockIdentityProviderConfigurationFactory idpFactory = new MockIdentityProviderConfigurationFactory();
        final SamlServiceBuilder samlServiceBuilder = new SamlServiceBuilderImpl();
        samlServiceBuilder.buildAuthenticationService(
                idpFactory, new MockMessageObserver(), new MockSamlConfigurationService());

        final SamlCoreService samlCoreService = InstanceUtil.getInstance(SamlCoreService.class);
        final NameID nameID = samlCoreService.buildSAMLObject(NameID.class);
        Assert.assertNotNull(nameID);
    }

    @Test
    public void testBuildLogoutRequest() {

        final MockIdentityProviderConfigurationFactory idpFactory = new MockIdentityProviderConfigurationFactory();
        final SamlServiceBuilder samlServiceBuilder = new SamlServiceBuilderImpl();
        samlServiceBuilder.buildAuthenticationService(
                idpFactory, new MockMessageObserver(), new MockSamlConfigurationService());

        final SamlCoreService samlCoreService = InstanceUtil.getInstance(SamlCoreService.class);
        final NameID nameID = samlCoreService.buildSAMLObject(NameID.class);
        final String sessionIndexValue = "123";
        nameID.setValue(sessionIndexValue);
        final LogoutRequest logoutRequest = samlCoreService.buildLogoutRequest(
                idpFactory.findIdentityProviderConfigurationById("test.com"), nameID, sessionIndexValue);
        Assert.assertNotNull(logoutRequest);
        Assert.assertEquals("urn:oasis:names:tc:SAML:2.0:logout:user", logoutRequest.getReason());
        Assert.assertEquals(sessionIndexValue, logoutRequest.getNameID().getValue());
        Assert.assertFalse(logoutRequest.getSessionIndexes().isEmpty());
        Assert.assertEquals(sessionIndexValue, logoutRequest.getSessionIndexes().get(0).getSessionIndex());
        Assert.assertEquals("https://test.dotcms.com/o/saml2/idp/logout?idpid=xxx", logoutRequest.getDestination());
    }
}
