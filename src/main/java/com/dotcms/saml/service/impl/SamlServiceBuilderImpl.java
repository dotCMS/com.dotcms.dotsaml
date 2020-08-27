package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfigurationFactory;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.SamlAuthenticationService;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.handler.AssertionResolverHandlerFactory;
import com.dotcms.saml.service.handler.AuthenticationResolverHandlerFactory;
import com.dotcms.saml.service.handler.HttpPostAssertionResolverHandlerImpl;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotcms.saml.service.internal.CredentialService;
import com.dotcms.saml.service.internal.EndpointService;
import com.dotcms.saml.service.internal.MetaDataService;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.InstanceUtil;
import org.apache.velocity.app.VelocityEngine;

import java.util.Collections;

public class SamlServiceBuilderImpl implements SamlServiceBuilder {


    private Initializer initializer = null;

    @Override
    public SamlConfigurationService buildSamlConfigurationService() {
        return new SamlConfigurationServiceImpl();
    }

    @Override
    public SamlAuthenticationService buildAuthenticationService(final IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
                                                                final VelocityEngine           velocityEngine,
                                                                final MessageObserver messageObserver,
                                                                final SamlConfigurationService samlConfigurationService) {

        if (null == this.initializer) {
            this.initFramework();
        }
        final CredentialService credentialService = new CredentialServiceImpl(samlConfigurationService);
        final EndpointService endpointService     = new EndpointServiceImpl(samlConfigurationService);
        final MetaDataService metaDataService     = new MetaDataServiceImpl(samlConfigurationService, messageObserver);
        final AssertionResolverHandlerFactory assertionResolverHandlerFactory =
                new AssertionResolverHandlerFactory(samlConfigurationService, messageObserver);
        final SamlCoreService samlCoreService =
                new SamlCoreServiceImpl(credentialService, endpointService, metaDataService,
                        messageObserver, samlConfigurationService, identityProviderConfigurationFactory);
        final MetaDescriptorService metaDescriptorService =
                new DefaultMetaDescriptorServiceImpl(samlConfigurationService, messageObserver,
                        samlCoreService, credentialService, endpointService);
        InstanceUtil.putInstance(MetaDescriptorService.class, metaDescriptorService);
        InstanceUtil.putInstance(SamlCoreService.class, samlCoreService);
        assertionResolverHandlerFactory.addAssertionResolverHandler(HttpPostAssertionResolverHandlerImpl.class.getName(),
                new HttpPostAssertionResolverHandlerImpl(messageObserver, samlCoreService, samlConfigurationService));
        final AuthenticationResolverHandlerFactory authenticationResolverHandlerFactory =
                new AuthenticationResolverHandlerFactory(samlConfigurationService, samlCoreService, velocityEngine, messageObserver);
        messageObserver.updateInfo(this.getClass().getName(), "Creating a new SamlAuthenticationService");

        return new OpenSamlAuthenticationServiceImpl(authenticationResolverHandlerFactory, assertionResolverHandlerFactory, samlCoreService,
                samlConfigurationService, messageObserver, metaDescriptorService, this.initializer);
    }

    private void initFramework() {

        this.initializer = new SamlInitializer();
        this.initializer.init(Collections.emptyMap());
    }
}
