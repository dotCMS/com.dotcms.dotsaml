package com.dotcms.saml.osgi;

import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.impl.SamlServiceBuilderImpl;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.servlets.InitServlet;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.wiring.BundleWiring;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * This activator will register the {@link SamlServiceBuilder} this class will provide the main facade
 * {@link com.dotcms.saml.SamlAuthenticationService} <br/>
 * In Addition there 3 interfaces that needs to be implemented on the client in order to interact with the custom client configuration.
 * @author jsanca
 */
public class Activator extends GenericBundleActivator {

    private final static String[] CLASSES = new String[]{
            "com.dotcms.saml.service.external.Attributes",
            "com.dotcms.saml.service.external.AttributesNotFoundException",
            "com.dotcms.saml.service.external.BindingType",
            "com.dotcms.saml.service.external.InvalidIssuerValueException",
            "com.dotcms.saml.service.external.MetaData",
            "com.dotcms.saml.service.external.NotNullEmailAllowedException",
            "com.dotcms.saml.service.external.SamlConstants",
            "com.dotcms.saml.service.external.SamlException",
            "com.dotcms.saml.service.external.SamlUnauthorizedException",
            "com.dotcms.saml.service.internal.SamlCoreService",
            "com.dotcms.saml.service.internal.EndpointService",
            "com.dotcms.saml.service.internal.CredentialService",
            "com.dotcms.saml.service.internal.CredentialProvider",
            "com.dotcms.saml.service.internal.MetaDataService",
            "com.dotcms.saml.service.internal.MetaDescriptorService",
            "com.dotcms.saml.service.impl.MetaDataServiceImpl",
            "com.dotcms.saml.service.impl.CredentialServiceImpl",
            "com.dotcms.saml.service.impl.EndpointServiceImpl",
            "com.dotcms.saml.service.impl.DefaultMetaDescriptorServiceImpl",
            "com.dotcms.saml.service.impl.OpenSamlAuthenticationServiceImpl",
            "com.dotcms.saml.service.impl.SamlConfigurationServiceImpl",
            "com.dotcms.saml.service.impl.SamlCoreServiceImpl",
            "com.dotcms.saml.service.impl.SamlServiceBuilderImpl",
            "com.dotcms.saml.service.impl.DotHTTPPOSTDeflateEncoder",
            "com.dotcms.saml.service.impl.DotHTTPRedirectDeflateEncoder",
            "com.dotcms.saml.utils.IdpConfigCredentialResolver",
            "com.dotcms.saml.utils.InstanceUtil",
            "com.dotcms.saml.utils.MetaDataXMLPrinter",
            "com.dotcms.saml.utils.SamlUtils",
            "org.opensaml.xml.util.Base64",
            "com.dotcms.saml.service.handler.AssertionResolverHandler",
            "com.dotcms.saml.service.handler.AssertionResolverHandlerFactory",
            "com.dotcms.saml.service.handler.AuthenticationHandler",
            "com.dotcms.saml.service.handler.HttpPOSTAuthenticationHandler",
            "com.dotcms.saml.service.handler.HttpRedirectAuthenticationHandler",
            "com.dotcms.saml.service.handler.HttpPostAssertionResolverHandlerImpl",
            "com.dotcms.saml.service.handler.AuthenticationResolverHandlerFactory",
            "com.dotcms.saml.service.handler.HttpPOSTLogoutHandler",
            "com.dotcms.saml.service.handler.HttpRedirectLogoutHandler",
            "com.dotcms.saml.service.handler.LogoutHandler",
            "com.dotcms.saml.service.handler.LogoutResolverHandlerFactory",
            "com.dotcms.saml.service.handler.HttpOktaLogoutHandler"
    };

    private ServiceRegistration samlServiceBuilder;

    @SuppressWarnings("unchecked")
    public void start(final BundleContext context) throws Exception {

        System.out.println("SAML OSGI STARTING INIT.....");
        //Create an instance of our SamlServiceBuilderImpl
        //Classloading
        final ClassLoader  currentThreadClassLoader = Thread.currentThread().getContextClassLoader();
        final ClassLoader bundleClassLoader         = this.getClass().getClassLoader();

        try {

            //this.initializeServices(context);
            final BundleWiring bundleWiring = context.getBundle().adapt(BundleWiring.class);
            final ClassLoader loader = bundleWiring.getClassLoader();
            final Map<String, Object> contextMap = new HashMap<>();
            final Initializer initializer = new SamlInitializer();

            System.out.println("currentThreadClassLoader: " + currentThreadClassLoader);
            System.out.println("bundleClassLoader: " + bundleClassLoader);
            System.out.println("bundleWiring: " + bundleWiring);

            contextMap.put("loader", currentThreadClassLoader);
            initializer.init(contextMap);

            final SamlServiceBuilderImpl samlServiceBuilderImpl = new SamlServiceBuilderImpl();
            samlServiceBuilderImpl.setInitializer(initializer);

            //Register the TikaServiceBuilder as a OSGI service
            this.samlServiceBuilder = context
                    .registerService(SamlServiceBuilder.class.getName(), samlServiceBuilderImpl,
                            new Hashtable<>());

            // this.loadClasses();

            System.out.println("SAML OSGI STARTED.....");
        } finally {
            if (null != currentThreadClassLoader) {
                Thread.currentThread().setContextClassLoader(currentThreadClassLoader);
            }
        }
    }

    private void loadClasses() {

        try {

            for (final String className : CLASSES) {
                loadClass(className);
            }

            try (InputStream inputStream = Activator.class.getResourceAsStream("/classes-report.txt")) {

                new BufferedReader(new InputStreamReader(inputStream)).lines()
                        .forEach(line -> loadClass(line));
            }
        } catch (Throwable e) {
            e.printStackTrace(System.out);
        }
    }

    private void loadClass (final String classname) {

        try {
            Class.forName(classname.replaceAll("/", ".")
                    .replace(".class", ""));
            //System.out.println(classname);
        } catch (Throwable e) {
            e.printStackTrace(System.out);
        }
    }

    public void stop(final BundleContext context) throws Exception {

        //Unregister the registered services
        this.samlServiceBuilder.unregister();
    }

}
