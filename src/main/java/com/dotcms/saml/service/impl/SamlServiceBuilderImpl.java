package com.dotcms.saml.service.impl;

import com.dotcms.saml.IdentityProviderConfigurationFactory;
import com.dotcms.saml.MessageObserver;
import com.dotcms.saml.SamlAuthenticationService;
import com.dotcms.saml.SamlConfigurationService;
import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.handler.AssertionResolverHandlerFactory;
import com.dotcms.saml.service.handler.AuthenticationResolverHandlerFactory;
import com.dotcms.saml.service.handler.HttpPostAssertionResolverHandlerImpl;
import com.dotcms.saml.service.handler.LogoutResolverHandlerFactory;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotcms.saml.service.internal.CredentialService;
import com.dotcms.saml.service.internal.EndpointService;
import com.dotcms.saml.service.internal.MetaDataService;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.internal.SamlCoreService;
import com.dotcms.saml.utils.InstanceUtil;
import com.dotcms.saml.utils.SignatureUtils;
import com.dotmarketing.util.Logger;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;

public class SamlServiceBuilderImpl implements SamlServiceBuilder {


    private Initializer initializer = null;

    public void setInitializer(Initializer initializer) {
        this.initializer = initializer;
    }

    @Override
    public SamlConfigurationService buildSamlConfigurationService() {
        return new SamlConfigurationServiceImpl();
    }

    @Override
    public SamlAuthenticationService buildAuthenticationService(final IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
                                                                final VelocityEngine           velocityEngine,
                                                                final MessageObserver messageObserver,
                                                                final SamlConfigurationService samlConfigurationService) {

        SamlAuthenticationService samlAuthenticationService = null;
        try {

            samlAuthenticationService = this.createOpenSamlAuthenticationService(identityProviderConfigurationFactory,
                    velocityEngine, messageObserver, samlConfigurationService);
        } catch (ClassNotFoundException | NoClassDefFoundError e) {

            Logger.info(this.getClass().getName(), "Could not upload the SamlAuthenticationService: " + e.getMessage());

            final ClassLoader  threadLoader = Thread.currentThread().getContextClassLoader();
            Logger.info(this.getClass().getName(), "Current classloader: " + threadLoader);

            try {

                final ClassLoader  samlServiceBuilderThreadLoader = this.getClass().getClassLoader();
                Logger.info(this.getClass().getName(), "Using temporally to init the SamlAuthenticationService classloader: " + samlServiceBuilderThreadLoader);
                Thread.currentThread().setContextClassLoader(samlServiceBuilderThreadLoader);
                try {
                    samlAuthenticationService = this.createOpenSamlAuthenticationService(identityProviderConfigurationFactory,
                            velocityEngine, messageObserver, samlConfigurationService);
                } catch (ClassNotFoundException classNotFoundException) {
                    Logger.error(this.getClass().getName(), e.getMessage(), e);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(threadLoader);
            }
        }

        return samlAuthenticationService;
    }

    private OpenSamlAuthenticationServiceImpl createOpenSamlAuthenticationService(final IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
                                                                                  final VelocityEngine velocityEngine,
                                                                                  final MessageObserver messageObserver,
                                                                                  final SamlConfigurationService samlConfigurationService) throws ClassNotFoundException {
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
        final LogoutResolverHandlerFactory logoutResolverHandlerFactory =
                new LogoutResolverHandlerFactory(samlConfigurationService, samlCoreService, velocityEngine, messageObserver);
        messageObserver.updateInfo(this.getClass().getName(), "Creating a new SamlAuthenticationService");

        return new OpenSamlAuthenticationServiceImpl(logoutResolverHandlerFactory, authenticationResolverHandlerFactory,
                assertionResolverHandlerFactory, samlCoreService,
                samlConfigurationService, messageObserver, metaDescriptorService, this.initializer);
    }

    private void initFramework() {

        this.initializer = new SamlInitializer();
        this.initializer.init(Collections.emptyMap());
    }
}
