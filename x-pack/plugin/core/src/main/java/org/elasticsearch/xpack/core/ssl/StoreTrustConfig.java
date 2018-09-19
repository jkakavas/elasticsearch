/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ssl;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.env.Environment;
import org.elasticsearch.xpack.core.ssl.cert.CertificateInfo;

import javax.net.ssl.X509ExtendedTrustManager;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Trust configuration that is backed by a {@link java.security.KeyStore}
 */
class StoreTrustConfig extends TrustConfig {

    final String trustStorePath;
    final String trustStoreType;
    final String trustStoreProvider;
    final SecureString trustStorePassword;
    final String trustStoreAlgorithm;

    /**
     * Create a new configuration based on the provided parameters
     *
     * @param trustStorePath      the path to the truststore
     * @param trustStorePassword  the password for the truststore
     * @param trustStoreAlgorithm the algorithm to use for reading the truststore
     */
    StoreTrustConfig(String trustStorePath, String trustStoreType, SecureString trustStorePassword, String trustStoreAlgorithm,
                     String trustStoreProvider) {
        this.trustStorePath = trustStorePath;
        this.trustStoreType = trustStoreType;
        // since we support reloading the truststore, we must store the passphrase in memory for the life of the node, so we
        // clone the password and never close it during our uses below
        this.trustStorePassword = Objects.requireNonNull(trustStorePassword, "truststore password must be specified").clone();
        this.trustStoreAlgorithm = trustStoreAlgorithm;
        this.trustStoreProvider = trustStoreProvider;
    }

    @Override
    X509ExtendedTrustManager createTrustManager(@Nullable Environment environment) {
        try {
            KeyStore trustStore = getTrustStore(environment);
            return CertParsingUtils.trustManager(trustStore, trustStoreAlgorithm);
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | NoSuchProviderException e) {
            throw new ElasticsearchException("failed to initialize a TrustManagerFactory", e);
        }
    }

    @Override
    Collection<CertificateInfo> certificates(Environment environment) throws GeneralSecurityException, IOException {
        final Path path = CertParsingUtils.resolvePath(trustStorePath, environment);
        final KeyStore trustStore = CertParsingUtils.readKeyStore(path, trustStoreType, trustStorePassword.getChars());
        final List<CertificateInfo> certificates = new ArrayList<>();
        final Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            final Certificate certificate = trustStore.getCertificate(alias);
            if (certificate instanceof X509Certificate) {
                final boolean hasKey = trustStore.isKeyEntry(alias);
                certificates.add(new CertificateInfo(trustStorePath, trustStoreType, alias, hasKey, (X509Certificate) certificate));
            }
        }
        return certificates;
    }

    @Override
    List<Path> filesToMonitor(@Nullable Environment environment) {
        if (trustStorePath == null) {
            return Collections.emptyList();
        }
        return Collections.singletonList(CertParsingUtils.resolvePath(trustStorePath, environment));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        StoreTrustConfig that = (StoreTrustConfig) o;

        if (trustStorePath != null ? !trustStorePath.equals(that.trustStorePath) : that.trustStorePath != null) return false;
        if (trustStorePassword != null ? !trustStorePassword.equals(that.trustStorePassword) : that.trustStorePassword != null)
            return false;
        return trustStoreAlgorithm != null ? trustStoreAlgorithm.equals(that.trustStoreAlgorithm) : that.trustStoreAlgorithm == null;
    }

    @Override
    public int hashCode() {
        int result = trustStorePath != null ? trustStorePath.hashCode() : 0;
        result = 31 * result + (trustStorePassword != null ? trustStorePassword.hashCode() : 0);
        result = 31 * result + (trustStoreAlgorithm != null ? trustStoreAlgorithm.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "trustStorePath=[" + trustStorePath +
                "], trustStoreAlgorithm=[" + trustStoreAlgorithm +
                "]";
    }

    private KeyStore getTrustStore(@Nullable Environment environment)
        throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
        if (null != trustStorePath) {
            try (InputStream in = Files.newInputStream(CertParsingUtils.resolvePath(trustStorePath, environment))) {
                KeyStore ks = KeyStore.getInstance(trustStoreType);
                ks.load(in, trustStorePassword.getChars());
                return ks;
            }
        } else if (null != trustStoreProvider) {
            KeyStore ks = KeyStore.getInstance(trustStoreType, trustStoreProvider);
            ks.load(null, trustStorePassword.getChars());
            return ks;
        }
        throw new IllegalArgumentException("trustStorePath and trustStoreProvider cannot both be null");
    }
}
