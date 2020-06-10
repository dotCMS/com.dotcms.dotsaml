package com.dotcms.saml.osgi;

import com.dotcms.saml.service.impl.SamlServiceBuilderImpl;
import com.dotcms.saml.service.external.SamlServiceBuilder;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

import java.util.Hashtable;

public class Activator implements BundleActivator {

    private ServiceRegistration samlServiceBuilder;

    @SuppressWarnings("unchecked")
    public void start(final BundleContext context) throws Exception {

        //Create an instance of our SamlServiceBuilderImpl
        final SamlServiceBuilderImpl samlServiceBuilderImpl = new SamlServiceBuilderImpl();

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
