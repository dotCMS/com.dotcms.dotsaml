package com.dotcms.saml.service.impl;

import com.dotcms.saml.service.external.IdentityProviderConfigurationFactory;
import com.dotcms.saml.service.external.MessageObserver;
import com.dotcms.saml.service.external.SamlAuthenticationService;
import com.dotcms.saml.service.external.SamlConfigurationService;
import com.dotcms.saml.service.external.SamlServiceBuilder;
import com.dotcms.saml.service.handler.AssertionResolverHandlerFactory;
import com.dotcms.saml.service.internal.CredentialService;
import com.dotcms.saml.service.internal.EndpointService;
import com.dotcms.saml.service.internal.MetaDataService;
import com.dotcms.saml.service.internal.MetaDescriptorService;
import com.dotcms.saml.service.internal.SamlCoreService;

public class SamlServiceBuilderImpl implements SamlServiceBuilder {

    @Override
    public SamlAuthenticationService buildAuthenticationService(final IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
                                                                final MessageObserver messageObserver,
                                                                final SamlConfigurationService samlConfigurationService) {

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

        messageObserver.updateInfo(this.getClass(), "Creating a new SamlAuthenticationService");

        return new OpenSamlAuthenticationServiceImpl(assertionResolverHandlerFactory, samlCoreService,
                samlConfigurationService, messageObserver, metaDescriptorService);
    }
}
