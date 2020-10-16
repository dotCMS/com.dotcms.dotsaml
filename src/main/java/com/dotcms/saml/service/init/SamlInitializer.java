package com.dotcms.saml.service.init;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;

import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Default initializer Responsibilities: - Init the Java Crypto. - Init Saml
 * Services. - Init Plugin Configuration and meta data.
 *
 * @author jsanca
 */
public class SamlInitializer implements Initializer {

	private static final long serialVersionUID = -5869927082029401479L;

	private final static AtomicBoolean initDone = new AtomicBoolean( false );

	public SamlInitializer() {
	}

	@Override
	public synchronized void init(final Map<String, Object> context) {

		final ClassLoader loader =
				null != context && context.containsKey("loader")?
					(ClassLoader)context.get("loader"):null;
		final Thread      thread = Thread.currentThread();

		try {

			if (null != loader) {

				thread.setContextClassLoader(InitializationService.class.getClassLoader());
			}

			System.out.println("Initializing SAML..." );
			InitializationService.initialize();

			System.out.println("SAML Init DONE" );
		} catch (final InitializationException e) {

			throw new RuntimeException( "Initialization failed", e );
		} finally {

			if (null != loader) {

				thread.setContextClassLoader(loader);
			}
		}

		System.out.println("Setting basic parser pool");

		if (XMLObjectProviderRegistrySupport.getParserPool() == null ) {

			XMLObjectProviderRegistrySupport.setParserPool(new BasicParserPool());
		}

		System.out.println("Doing instance of Java Crypto validator");

		try {

			final JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
			System.out.println("Initializing Java Crypto validator");
			javaCryptoValidationInitializer.init();
		} catch (final InitializationException initializationException) {

			initializationException.printStackTrace();
		} catch (final Exception e) {

			e.printStackTrace();
		}

		System.out.println("Getting the Security Providers");
		for (final Provider jceProvider : Security.getProviders()) {

			System.out.println(jceProvider.getInfo());
		}

		initDone.set( true );
	}

	@Override
	public boolean isInitializationDone() {

		return initDone.get();
	}

}
