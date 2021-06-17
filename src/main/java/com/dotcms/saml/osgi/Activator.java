package com.dotcms.saml.osgi;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import com.dotcms.auth.providers.saml.v1.DotSamlResource;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.filters.interceptor.saml.SamlWebInterceptor;
import com.dotcms.rest.config.RestServiceUtil;
import com.dotcms.saml.DotSamlProxyFactory;
import com.dotcms.saml.SamlServiceBuilder;
import com.dotcms.saml.service.impl.SamlServiceBuilderImpl;
import com.dotcms.saml.service.init.Initializer;
import com.dotcms.saml.service.init.SamlInitializer;
import com.dotcms.security.apps.AppSecretSavedEvent;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.filters.AutoLoginFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import io.vavr.control.Try;

/**
 * This activator will register the {@link SamlServiceBuilder} this class will provide the main
 * facade {@link com.dotcms.saml.SamlAuthenticationService} <br/>
 * In Addition there 3 interfaces that needs to be implemented on the client in order to interact
 * with the custom client configuration.
 * 
 * @author jsanca
 */
public class Activator extends GenericBundleActivator {

    private ServiceRegistration samlServiceBuilder;

    private String interceptorName;
    
    
    private final String DOT_SAML_ACTIVATED="DOT_SAML_ACTIVATED";
    

    private final Class clazz = DotSamlResource.class;

    private final String VERSION = "21.04";

    private final long   buildNumber = 1;

    @SuppressWarnings("unchecked")
    public void start(final BundleContext context) throws Exception {

        try {
            activate(context);
        }
        catch(Exception e) {
            Logger.warn(this.getClass(), "dotSAML failed to activate:" + e.getMessage(), e);
            System.setProperty(DOT_SAML_ACTIVATED, null);
        }
    }
    
    
    private void activate(final BundleContext context) {
        
        
        if(System.getProperty(DOT_SAML_ACTIVATED)!=null) {
            Logger.warn(this.getClass(), "dotSAML already activated, returning");
            return;
        }
        
        synchronized (Config.class) {

            if(System.getProperty(DOT_SAML_ACTIVATED)!=null) {
                Logger.warn(this.getClass(), "dotSAML already activated, returning");
                return;
            }
            
            
            
            System.out.println("SAML OSGI STARTING INIT.....");
            System.out.println("SAML version: " + VERSION + ", build number: " + buildNumber);
    
    
            final Map<String, Object> contextMap = new HashMap<>();
            final Initializer initializer = new SamlInitializer();
    
            initializer.init(contextMap);
    
            final SamlServiceBuilderImpl samlServiceBuilderImpl = new SamlServiceBuilderImpl();
            samlServiceBuilderImpl.setInitializer(initializer);
    
            // Register the TikaServiceBuilder as a OSGI service
            this.samlServiceBuilder = context.registerService(SamlServiceBuilder.class.getName(), samlServiceBuilderImpl,
                            new Hashtable<>());
    
            Logger.info(this.getClass().getName(), "Adding the SAML Web Filter");
    
            addSamlWebInterceptor();
    
    
            Logger.info(this.getClass().getName(), "Adding the SAML Web Service: " + clazz.getName());
            RestServiceUtil.addResource(clazz);
    
            Logger.info(this.getClass().getName(), "Subscribing to  AppSecretSavedEvent events");
            Try.run (()-> APILocator.getLocalSystemEventsAPI().
                    subscribe(AppSecretSavedEvent.class,  DotSamlProxyFactory.getInstance()))
                    .onFailure(e -> Logger.error(this.getClass().getName(), e.getMessage()));
    
    
            System.out.println("SAML OSGI STARTED.....");
            
            System.setProperty(DOT_SAML_ACTIVATED, "true");
        }
    }
    
    
    
    

    private void addSamlWebInterceptor() {
        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                FilterWebInterceptorProvider.getInstance(Config.CONTEXT);

        final WebInterceptorDelegate delegate =
                filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);

        final SamlWebInterceptor samlWebInterceptor = new SamlWebInterceptor();
        this.interceptorName = samlWebInterceptor.getName();

        // in old versions of dotcms may still have the interceptor on core, so lets remove it before add a new one
        Try.run(()->delegate.remove(this.interceptorName, true))
                .onFailure(e -> Logger.error(this.getClass().getName(), e.getMessage()));

        delegate.add(samlWebInterceptor);
    }


    public void stop(final BundleContext context) throws Exception {

        Logger.info(this.getClass().getName(), "UnSubscribing to  AppSecretSavedEvent events.");
        Try.run (()-> APILocator.getLocalSystemEventsAPI().
                unsubscribe(AppSecretSavedEvent.class,  DotSamlProxyFactory.getInstance().getClass().getName()))
                .onFailure(e -> Logger.error(this.getClass().getName(), e.getMessage()));

        Logger.info(this.getClass().getName(), "Removing the SAML Web Service");
        RestServiceUtil.removeResource(clazz);

        Logger.info(this.getClass().getName(), "Removing the SAML Web Filter");
        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                FilterWebInterceptorProvider.getInstance(Config.CONTEXT);

        final WebInterceptorDelegate delegate =
                filterWebInterceptorProvider.getDelegate(AutoLoginFilter.class);

        delegate.remove(this.interceptorName, true);

        // Unregister the registered services
        this.samlServiceBuilder.unregister();
        
        System.setProperty(DOT_SAML_ACTIVATED, null);
        
    }

}
