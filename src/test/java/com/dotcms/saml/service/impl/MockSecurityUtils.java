package com.dotcms.saml.service.impl;

import sun.security.x509.*;

import java.io.ByteArrayOutputStream;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Date;
import java.io.IOException;
public class MockSecurityUtils {

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    public final static String LINE_SEPARATOR = System.getProperty("line.separator");

    /**
     * Create a self-signed X.509 Certificate
     * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair the KeyPair
     * @param days how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    public static X509Certificate generateCertificate(final String dn, final KeyPair pair, final int days, final String algorithm){

        try {
            final PrivateKey privkey = pair.getPrivate();
            final X509CertInfo info = new X509CertInfo();
            final Date from = new Date();
            final Date to = new Date(from.getTime() + days * 86400000l);
            final CertificateValidity interval = new CertificateValidity(from, to);
            final BigInteger sn = new BigInteger(64, new SecureRandom());
            final X500Name owner = new X500Name(dn);

            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, owner);
            info.set(X509CertInfo.ISSUER, owner);
            info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

            // Sign the cert to identify the algorithm that's used.
            X509CertImpl cert = new X509CertImpl(info);
            cert.sign(privkey, algorithm);

            // Update the algorith, and resign.
            algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
            info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
            cert = new X509CertImpl(info);
            cert.sign(privkey, algorithm);
            return cert;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateKeyPair () {

        final KeyPairGenerator keyPairGenerator;
        try {

            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException e) {

            throw new RuntimeException(e);
        }
    }

    public static X509Certificate generateCertificate (final KeyPair keyPair) {

        final String distinguishedName = "CN=Test, L=London, C=GB";
        return generateCertificate(distinguishedName, keyPair, 365, "SHA256withRSA");
    }

    public static String formatCrtFileContents(final Certificate certificate) throws CertificateEncodingException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        final String prettified_cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
        return prettified_cert;
    }

    public static String generatePrivateKeyAsString(final KeyPair keyPair, final Certificate certificate) {

        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {

            final Certificate[] chain = {certificate};
            final KeyStore keyStore   = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry("main", keyPair.getPrivate(), "654321".toCharArray(), chain);
            keyStore.store(out, "123456".toCharArray());
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        return out.toString();
    }

    public static String generatePrivateKeyAsString(final KeyPair keyPair) {

        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        final byte[] rawCrtText = keyPair.getPrivate().getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        final String prettified_cert = BEGIN_PRIVATE_KEY + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_PRIVATE_KEY;
        return prettified_cert;

    }
}
