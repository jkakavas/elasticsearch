/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.client;

import org.elasticsearch.xpack.core.ssl.CertParsingUtils;
import org.elasticsearch.xpack.core.ssl.PemUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class SslConfig {

    public static final String SSL = "ssl";
    private static final String SSL_DEFAULT = "false";

    public static final String SSL_PROTOCOL = "ssl.protocol";
    private static final String SSL_PROTOCOL_DEFAULT = "TLS"; // SSL alternative

    public static final String SSL_KEYSTORE_LOCATION = "ssl.keystore.location";
    private static final String SSL_KEYSTORE_LOCATION_DEFAULT = "";

    public static final String SSL_KEYSTORE_PASS = "ssl.keystore.pass";
    private static final String SSL_KEYSTORE_PASS_DEFAULT = "";

    public static final String SSL_KEYSTORE_TYPE = "ssl.keystore.type";
    private static final String SSL_KEYSTORE_TYPE_DEFAULT = "JKS"; // PCKS12

    public static final String SSL_KEY = "ssl.key";
    private static final String SSL_KEY_DEFAULT = "";

    public static final String SSL_KEY_PASS = "ssl.key.pass";
    private static final String SSL_KEY_PASS_DEFAULT = "";

    public static final String SSL_CERTIFICATE = "ssl.certificate";
    private static final String SSL_CERTIFICATE_DEFAULT = "";

    public static final String SSL_TRUSTSTORE_LOCATION = "ssl.truststore.location";
    private static final String SSL_TRUSTSTORE_LOCATION_DEFAULT = "";

    public static final String SSL_TRUSTSTORE_PASS = "ssl.truststore.pass";
    private static final String SSL_TRUSTSTORE_PASS_DEFAULT = "";

    public static final String SSL_TRUSTSTORE_TYPE = "ssl.truststore.type";
    private static final String SSL_TRUSTSTORE_TYPE_DEFAULT = "JKS";

    public static final String SSL_CERTIFICATE_AUTHORITIES = "ssl.certificateAuthorities";
    private static final String SSL_CERTIFICATE_AUTHORITIES_DEFAULT = "";

    static final Set<String> OPTION_NAMES = new LinkedHashSet<>(Arrays.asList(SSL, SSL_PROTOCOL,
        SSL_KEYSTORE_LOCATION, SSL_KEYSTORE_PASS, SSL_KEYSTORE_TYPE, SSL_KEY, SSL_CERTIFICATE,
        SSL_TRUSTSTORE_LOCATION, SSL_TRUSTSTORE_PASS, SSL_TRUSTSTORE_TYPE, SSL_CERTIFICATE_AUTHORITIES));

    private final boolean enabled;
    private final String protocol, keystoreLocation, keystorePass, keystoreType;
    private final String truststoreLocation, truststorePass, truststoreType;
    private final String keyLocation;
    private final String keyPass;
    private final String certificateLocation;
    private final List<String> certificateAuthorities;
    private final SSLContext sslContext;

    SslConfig(Properties settings) {
        enabled = StringUtils.parseBoolean(settings.getProperty(SSL, SSL_DEFAULT));
        protocol = settings.getProperty(SSL_PROTOCOL, SSL_PROTOCOL_DEFAULT);
        keystoreLocation = settings.getProperty(SSL_KEYSTORE_LOCATION, SSL_KEYSTORE_LOCATION_DEFAULT);
        keystorePass = settings.getProperty(SSL_KEYSTORE_PASS, SSL_KEYSTORE_PASS_DEFAULT);
        keystoreType = settings.getProperty(SSL_KEYSTORE_TYPE, SSL_KEYSTORE_TYPE_DEFAULT);
        keyLocation = settings.getProperty(SSL_KEY, SSL_KEY_DEFAULT);
        keyPass = settings.getProperty(SSL_KEY_PASS, SSL_KEY_PASS_DEFAULT);
        certificateLocation = settings.getProperty(SSL_CERTIFICATE, SSL_CERTIFICATE_DEFAULT);
        truststoreLocation = settings.getProperty(SSL_TRUSTSTORE_LOCATION, SSL_TRUSTSTORE_LOCATION_DEFAULT);
        truststorePass = settings.getProperty(SSL_TRUSTSTORE_PASS, SSL_TRUSTSTORE_PASS_DEFAULT);
        truststoreType = settings.getProperty(SSL_TRUSTSTORE_TYPE, SSL_TRUSTSTORE_TYPE_DEFAULT);
        certificateAuthorities = Arrays.asList(
            settings.getProperty(SSL_CERTIFICATE_AUTHORITIES, SSL_CERTIFICATE_AUTHORITIES_DEFAULT).split(","));
        sslContext = enabled ? createSSLContext() : null;
    }

    // ssl
    boolean isEnabled() {
        return enabled;
    }

    SSLSocketFactory sslSocketFactory() {
        return sslContext.getSocketFactory();
    }

    private SSLContext createSSLContext() {
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance(protocol);
            ctx.init(loadKeyManagers(), loadTrustManagers(), null);
        } catch (Exception ex) {
            throw new ClientException("Failed to initialize SSL - " + ex.getMessage(), ex);
        }

        return ctx;
    }

    private KeyManager[] loadKeyManagers() throws GeneralSecurityException, IOException {
        if (StringUtils.hasText(keystoreLocation)) {
            char[] pass = (StringUtils.hasText(keystorePass) ? keystorePass.trim().toCharArray() : null);
            KeyManagerFactory kmFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = loadKeyStore(keystoreLocation, pass, keystoreType);
            kmFactory.init(keyStore, pass);
            return kmFactory.getKeyManagers();
        } else if (StringUtils.hasText(keyLocation)) {
            String keyPassword = keyPass.trim();
            Path certPath = Paths.get(certificateLocation);
            Path keyPath = Paths.get(keyLocation);
            if (Files.exists(certPath) == false) {
                throw new ClientException(
                    "Expected to find certificate file at [" + certPath + "] but was unable to. Make sure you have specified a valid URI.");
            }
            if (Files.exists(keyPath) == false) {
                throw new ClientException(
                    "Expected to find key file at [" + keyPath + "] but was unable to. Make sure you have specified a valid URI.");
            }
            KeyManager km = CertParsingUtils.keyManager(CertParsingUtils.readCertificates(Collections.singletonList(certPath)),
                PemUtils.readPrivateKey(keyPath, keyPassword::toCharArray), keyPass.toCharArray());
            return new KeyManager[]{km};
        }
        return null;
    }


    private KeyStore loadKeyStore(String location, char[] pass, String keyStoreType) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        Path path = Paths.get(location);

        if (!Files.exists(path)) {
           throw new ClientException(
                   "Expected to find keystore file at [" + location + "] but was unable to. Make sure you have specified a valid URI.");
        }

        try (InputStream in = Files.newInputStream(Paths.get(location), StandardOpenOption.READ)) {
            keyStore.load(in, pass);
        } catch (Exception ex) {
            throw new ClientException("Cannot open keystore [" + location + "] - " + ex.getMessage(), ex);
        } finally {

        }
        return keyStore;
    }

    private TrustManager[] loadTrustManagers() throws GeneralSecurityException, IOException {


        if (StringUtils.hasText(truststoreLocation)) {
            char[] pass = (StringUtils.hasText(truststorePass) ? truststorePass.trim().toCharArray() : null);
            KeyStore keyStore = loadKeyStore(truststoreLocation, pass, truststoreType);
            TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmFactory.init(keyStore);
            return tmFactory.getTrustManagers();
        } else if (certificateAuthorities.isEmpty() == false) {
            List<Path> trustedCerts = certificateAuthorities.stream().map(p -> Paths.get(p)).filter(p -> Files.exists(p) == false).
                collect(Collectors.toList());
            // We could return a null TrustManager[] and imply that they system truststore should be used. However, we assume that
            // if the user explicitly set the trusted authorities, they want to use only these.
            if (trustedCerts.isEmpty()) {
                throw new ClientException("None of the specified certificate authorities certificates could be found. Make sure you have " +
                    "specified valid URIs");
            }
            TrustManager tm = CertParsingUtils.trustManager(CertParsingUtils.readCertificates(trustedCerts));
            return new TrustManager[]{tm};
        }
        return null;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        SslConfig other = (SslConfig) obj;
        return Objects.equals(enabled, other.enabled)
                && Objects.equals(protocol, other.protocol)
                && Objects.equals(keystoreLocation, other.keystoreLocation)
                && Objects.equals(keystorePass, other.keystorePass)
                && Objects.equals(keystoreType, other.keystoreType)
                && Objects.equals(truststoreLocation, other.truststoreLocation)
                && Objects.equals(truststorePass, other.truststorePass)
                && Objects.equals(truststoreType, other.truststoreType);
    }

    public int hashCode() {
        return getClass().hashCode();
    }
}
