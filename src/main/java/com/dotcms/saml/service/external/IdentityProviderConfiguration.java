package com.dotcms.saml.service.external;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

/**
 * This interface provides to the SAML bundle the configuration needed per IDP per host.
 * @see IdentityProviderConfigurationFactory
 * @author jsanca
 */
public interface IdentityProviderConfiguration {

    /**
     * Returns true if the Identify provider is enable
     * @return boolean
     */
    boolean isEnabled();
    /**
     * Returns the service provider id url
     * @return String
     */
    String getSpIssuerURL();

    /**
     * Returns the identity provider name
     * @return String
     */
    String getIdpName();

    /**
     * Get Identifier
     * @return
     */
    String getId();

    /**
     * Get Service Provider endpoint host name
     * @return String
     */
    String getSpEndpointHostname();

    /**
     * Get the signature validation type
     * @return String
     */
    String getSignatureValidationType();

    /**
     * Retrieves the metadata Path
     * @return Path
     */
    Path getIdPMetadataFile();

    /**
     * Returns the public certificate File
     * @return File
     */
    File getPublicCert();

    /**
     * Returns the private certificate File
     * @return File
     */
    File getPrivateKey();

    /**
     * Get the optional property for the SAML configuration
     * @param propertyKey {@link String}
     * @return Object
     */
    Object getOptionalProperty(String propertyKey);

    /**
     * Returns true if the optional property exists
     * @param propertyKey {@link String}
     * @return boolean
     */
    boolean containsOptionalProperty(String propertyKey);
}
