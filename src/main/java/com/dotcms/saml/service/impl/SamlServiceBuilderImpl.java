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
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.wiring.BundleWiring;

import java.util.HashMap;
import java.util.Map;

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

        //final ClassLoader previous = Thread.currentThread().getContextClassLoader();

        try {

            //System.out.println("Setting class loader: " + getClass().getClassLoader() + ", previous class loader: " + previous);
            //Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            System.out.println("buildAuthenticationService: identityProviderConfigurationFactory = " + identityProviderConfigurationFactory +
                    ",velocityEngine = " + velocityEngine + ",messageObserver = " + messageObserver + ", samlConfigurationService = " + samlConfigurationService);
            final SamlAuthenticationService samlAuthenticationService =
                    getOpenSamlAuthenticationService(identityProviderConfigurationFactory, velocityEngine, messageObserver, samlConfigurationService);

            System.out.println("buildAuthenticationService: DONE");
            return samlAuthenticationService;
        } catch (Throwable e) {

            System.out.println("Error on buildAuthenticationService");
            System.out.println(e.getMessage());
            e.printStackTrace(System.out);
            messageObserver.updateError(SamlServiceBuilderImpl.class.getName(), e.getMessage(), e);
            return null;
        } finally {

            //Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private OpenSamlAuthenticationServiceImpl getOpenSamlAuthenticationService(final IdentityProviderConfigurationFactory identityProviderConfigurationFactory,
                                                                               final VelocityEngine velocityEngine,
                                                                               final MessageObserver messageObserver,
                                                                               final SamlConfigurationService samlConfigurationService) {
        if (null == this.initializer) {
            System.out.println("Doing initFramework");
            this.initFramework(messageObserver);
        } else {
            System.out.println("Init was done, initializer: " + this.initializer);
        }


        System.out.println("Doing init of EndpointService");
        messageObserver.updateInfo(this.getClass().getName(), "Doing init of CredentialService");
        final EndpointService endpointService     = new EndpointServiceImpl(samlConfigurationService);
        System.out.println("Doing init of MetaDataService");
        final MetaDataService metaDataService     = new MetaDataServiceImpl(samlConfigurationService, messageObserver);

        System.out.println("Doing init of CredentialService");
        final CredentialService credentialService = this.createCredentialService(messageObserver, samlConfigurationService);

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

    private CredentialServiceImpl createCredentialService(final MessageObserver messageObserver, final SamlConfigurationService samlConfigurationService) {
        try {

            System.out.println("Creating the CredentialService, samlConfigurationService: " + samlConfigurationService);
            messageObserver.updateInfo(this.getClass().getName(), "Creating the CredentialService, samlConfigurationService: " + samlConfigurationService);
            final CredentialServiceImpl credentialService = new CredentialServiceImpl(samlConfigurationService);
            System.out.println("Created the CredentialService");
            messageObserver.updateInfo(this.getClass().getName(), "Created the CredentialService");
            return credentialService;
        } catch (Throwable e) {

            System.out.println(e.getMessage());
            e.printStackTrace(System.out);
            messageObserver.updateError(SamlServiceBuilderImpl.class.getName(), e.getMessage(), e);
            return null;
        }
    }

    private void initFramework(final MessageObserver messageObserver) {

        final BundleContext context          = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        final BundleWiring bundleWiring      = context.getBundle().adapt(BundleWiring.class);
        final ClassLoader loader             = bundleWiring.getClassLoader();
        final Map<String, Object> contextMap = new HashMap<>();

        System.out.println("Doing SAML initFramework");
        messageObserver.updateInfo(this.getClass().getName(), "Doing SAML initFramework");
        contextMap.put("loader", loader);
        this.initializer = new SamlInitializer();
        try {

            this.initializer.init(contextMap);
        } catch (Throwable e) {

            e.printStackTrace();
            messageObserver.updateError(this.getClass().getName(), e.getMessage(), e);
        }

        messageObserver.updateInfo(this.getClass().getName(), "DONE SAML initFramework");
    }

    public void setInitializer(Initializer initializer) {
        this.initializer = initializer;
    }
}
