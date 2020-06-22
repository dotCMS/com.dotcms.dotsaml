package com.dotcms.saml.service.init;

import com.dotcms.saml.service.external.MessageObserver;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;

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

	private final AtomicBoolean   initDone = new AtomicBoolean( false );
	private final MessageObserver messageObserver;

	public SamlInitializer(final MessageObserver messageObserver) {
		this.messageObserver = messageObserver;
	}

	@Override
	public synchronized void init(final Map<String, Object> context) {

		final JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();

		try {

			this.messageObserver.updateInfo(this.getClass(), "Initializing Java Crypto validator");
			javaCryptoValidationInitializer.init();
		} catch (final InitializationException initializationException) {

			initializationException.printStackTrace();
		}

		this.messageObserver.updateInfo(this.getClass(), "Getting the Security Providers");
		for (final Provider jceProvider : Security.getProviders()) {

			this.messageObserver.updateInfo(this.getClass(), jceProvider.getInfo());
		}

		try {

			this.messageObserver.updateInfo( this.getClass(), "Initializing SAML..." );
			InitializationService.initialize();
			
			if (XMLObjectProviderRegistrySupport.getParserPool() == null ) {

				XMLObjectProviderRegistrySupport.setParserPool(new BasicParserPool());
			}
		} catch ( InitializationException e ) {

			throw new RuntimeException( "Initialization failed", e );
		}

		this.initDone.set( true );
	}

	@Override
	public boolean isInitializationDone()
	{

		return this.initDone.get();
	}

}
