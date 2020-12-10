/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.cli;

import joptsimple.OptionSet;
import org.elasticsearch.cli.*;
import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.env.Environment;

import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.zip.ZipEntry;

public class EsWrapper extends LoggingAwareMultiCommand {
    EsWrapper() {
        super("some description here");
        subcommands.put("init", new ClusterInitCommand());
        subcommands.put("join", new ClusterJoinCommand());
    }

    static final class ClusterInitCommand extends EnvironmentAwareCommand {

        ClusterInitCommand() {
            super("description");
        }

        @Override protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {

        }
    }

    static final class ClusterJoinCommand extends EnvironmentAwareCommand {

        ClusterJoinCommand() {
            super("description");
        }

        @Override protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {

        }

        void generateAndWriteSignedCertificates(
            Path output,
            boolean writeZipFile,
            OptionSet options,
            Collection<CertificateTool.CertificateInformation> certs,
            CertificateTool.CAInfo caInfo,
            Terminal terminal) throws Exception {

            assert certs.size() == 1;
            CertificateTool.CertificateInformation certificateInformation = certs.iterator().next();
            CertificateTool.CertificateAndKey pair = generateCertificateAndKey(certificateInformation, caInfo, keySize, days);
            fullyWriteFile(output, stream -> writePkcs12(output.getFileName().toString(),
                stream,
                certificateInformation.name.originalName,
                pair,
                caInfo == null ? null : caInfo.certAndKey.cert,
                outputPassword,
                terminal));

        }

        static void writePkcs12(String fileName, OutputStream output, String alias, CertificateTool.CertificateAndKey pair, X509Certificate caCert,
            char[] password, Terminal terminal) throws Exception {
            final KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
            pkcs12.load(null);
            withPassword(fileName, password, terminal, p12Password -> {

                    pkcs12.setKeyEntry(alias, pair.key, p12Password, new Certificate[]{pair.cert});
                    if (caCert != null) {
                        pkcs12.setCertificateEntry("ca", caCert);
                    }
                    pkcs12.store(output, p12Password);
                    return null;

            });
        }

        private static <T, E extends Exception> T withPassword(String description, char[] password, Terminal terminal,
            CheckedFunction<char[], T, E> body) throws E {
            if (password == null) {
                char[] promptedValue = terminal.readSecret("Enter password for " + description + " : ");
                try {
                    return body.apply(promptedValue);
                } finally {
                    Arrays.fill(promptedValue, (char) 0);
                }
            } else {
                return body.apply(password);
            }
        }

        private CertificateTool.CertificateAndKey generateCertificateAndKey(
            CertificateTool.CertificateInformation certificateInformation, CertificateTool.CAInfo caInfo, int keySize, int days)
            throws Exception {
            KeyPair keyPair = CertGenUtils.generateKeyPair(keySize);
            Certificate certificate;
            if (caInfo != null) {
                certificate = CertGenUtils.generateSignedCertificate(certificateInformation.name.x500Principal,
                    getSubjectAlternativeNamesValue(certificateInformation.ipAddresses,
                        certificateInformation.dnsNames,
                        certificateInformation.commonNames),
                    keyPair,
                    caInfo.certAndKey.cert,
                    caInfo.certAndKey.key,
                    days);
            } else {
                certificate = CertGenUtils.generateSignedCertificate(certificateInformation.name.x500Principal,
                    getSubjectAlternativeNamesValue(certificateInformation.ipAddresses,
                        certificateInformation.dnsNames,
                        certificateInformation.commonNames),
                    keyPair,
                    null,
                    null,
                    false,
                    days,
                    null);
            }
            return new CertificateTool.CertificateAndKey((X509Certificate) certificate, keyPair.getPrivate());
        }
    }
}
