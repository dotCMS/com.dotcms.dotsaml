/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.dotcms.saml.osgi;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.osgi.framework.BundleContext;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.rest.config.RestServiceUtil;
import com.dotcms.saml.cache.SamlCache;
import com.dotcms.saml.cache.SamlCacheImpl;
import com.dotcms.saml.rest.DotSamlRestService;
import com.dotcms.saml.rest.api.v1.DotSamlResource;
import com.dotcms.saml.util.BundleConfigProperties;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.CacheLocator;
import com.dotmarketing.business.DotStateException;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.filters.InterceptorFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.portlets.contentlet.business.DotContentletStateException;
import com.dotmarketing.portlets.languagesmanager.model.Language;
import com.dotmarketing.util.Config;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.liferay.portal.language.LanguageException;
import com.liferay.portal.language.LanguageUtil;

public final class Activator extends GenericBundleActivator {


    private LoggerContext pluginLoggerContext;

    Class[] samlResourceClasses = {DotSamlResource.class, DotSamlRestService.class};



    @Override
    public void start(BundleContext context) throws Exception {



        // Initializing log4j...
        LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();
        // Initialing the log4j context of this plugin based on the dotCMS logger context
        pluginLoggerContext = (LoggerContext) LogManager.getContext(this.getClass().getClassLoader(), false, dotcmsLoggerContext,
                        dotcmsLoggerContext.getConfigLocation());


        initializeServices(context);
        for (Class clazz : samlResourceClasses) {
            RestServiceUtil.addResource(clazz);
        }

        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                        FilterWebInterceptorProvider.getInstance(Config.CONTEXT);
        final WebInterceptorDelegate delegate = filterWebInterceptorProvider.getDelegate(InterceptorFilter.class);
        // delegate.addFirst(clickhouseInterceptor);
        String[] xmls = new String[] {"conf/portlet.xml"};
        registerPortlets(context, xmls);
        buildLanguageKeys();
    }

    @Override
    public void stop(BundleContext context) throws Exception {

        CacheLocator.getCacheAdministrator().flushGroupLocalOnly(new SamlCacheImpl().getPrimaryGroup(), true);
        SamlCache.INSTANCE.get().clearCache();

        final FilterWebInterceptorProvider filterWebInterceptorProvider =
                        FilterWebInterceptorProvider.getInstance(Config.CONTEXT);
        final WebInterceptorDelegate delegate = filterWebInterceptorProvider.getDelegate(InterceptorFilter.class);
        // delegate.remove(clickhouseInterceptor.getName(), true);

        // Unregister all the bundle services
        unregisterServices(context);

        for (Class clazz : samlResourceClasses) {
            RestServiceUtil.removeResource(clazz);
        }

        // Shutting down log4j in order to avoid memory leaks
        Log4jUtil.shutdown(pluginLoggerContext);
    }


    private final static String LANGUAGE_VARIABLE_FILE = "Language-ext.properties";


    private void buildLanguageKeys() throws LanguageException, DotContentletStateException, DotStateException, DotDataException,
                    DotSecurityException, IOException {
        Map<String, String> keys = new HashMap<>();

        Properties properties = new Properties();
        try ( InputStream in = BundleConfigProperties.class.getResourceAsStream("/" + LANGUAGE_VARIABLE_FILE)){
            properties.load(in);
        } 
        Enumeration propKeys  = properties.keys();
        while(propKeys.hasMoreElements()) {
            String propKey = (String) propKeys.nextElement();
            keys.put(propKey, properties.getProperty(propKey));
        }
        

        for (Language lang : APILocator.getLanguageAPI().getLanguages()) {
            APILocator.getLanguageAPI().saveLanguageKeys(lang, keys, new HashMap<>(), ImmutableSet.of());
        }



    }



}
