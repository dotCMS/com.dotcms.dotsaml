package com.dotcms.saml.service.external;

import java.io.File;
import java.nio.file.Path;

public interface IdentityProviderConfiguration {

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


    Path getIdPMetadataFile();

    File getPublicCert();

    File getPrivateKey();
}
