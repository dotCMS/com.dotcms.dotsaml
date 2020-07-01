package com.dotcms.saml.osgi;

import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.impl.SamlServiceBuilderImpl;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotmarketing.osgi.GenericBundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.wiring.BundleWiring;

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

    private ServiceRegistration samlServiceBuilder;

    @SuppressWarnings("unchecked")
    public void start(final BundleContext context) throws Exception {

        //Create an instance of our SamlServiceBuilderImpl
        //Classloading
        final BundleWiring bundleWiring      = context.getBundle().adapt(BundleWiring.class);
        final ClassLoader loader             = bundleWiring.getClassLoader();
        final Map<String, Object> contextMap = new HashMap<>();
        final Initializer initializer        = new SamlInitializer();

        contextMap.put("loader", loader);
        initializer.init(contextMap);


        final SamlServiceBuilderImpl samlServiceBuilderImpl = new SamlServiceBuilderImpl();

        System.out.println("SAML SAML SAML OSGI START.....");

        //Register the TikaServiceBuilder as a OSGI service
        this.samlServiceBuilder = context
                .registerService(SamlServiceBuilder.class.getName(), samlServiceBuilderImpl,
                        new Hashtable<>());
    }

    public void stop(final BundleContext context) throws Exception {

        //Unregister the registered services
        this.samlServiceBuilder.unregister();
    }

}
