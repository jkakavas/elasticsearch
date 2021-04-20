/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.cli;

import joptsimple.OptionSet;
import org.elasticsearch.cli.EnvironmentAwareCommand;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.env.Environment;

import javax.security.auth.x500.X500Principal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.xpack.security.cli.CertificateAndKeyUtils.fullyWriteFile;
import static org.elasticsearch.xpack.security.cli.CertificateAndKeyUtils.generateCA;
import static org.elasticsearch.xpack.security.cli.CertificateAndKeyUtils.getHostname;
import static org.elasticsearch.xpack.security.cli.CertificateAndKeyUtils.getIpAddress;

public class PreConfigureSecurity extends EnvironmentAwareCommand {

    PreConfigureSecurity(){
        super("Configures security");
    }

    public static void main(String[] args) throws Exception {
        exit(new PreConfigureSecurity().main(args, Terminal.DEFAULT));
    }

    @Override protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {
        generateKeysAndCertificates(env);
        updateConfiguration(env);
    }

    private void generateKeysAndCertificates(Environment env) throws Exception {
        final CertificateAndKeyUtils.CertificateInformation
            http =
            new CertificateAndKeyUtils.CertificateInformation(new X500Principal("CN=" + getHostname()),
                Collections.singletonList(getIpAddress()),
                List.of(getHostname(), "localhost"),
                Collections.emptyList());
        final CertificateAndKeyUtils.CAInfo httpCa = generateCA();
        fullyWriteFile(
            Paths.get(env.configFile().toAbsolutePath().toString(), "httpCa.p12"),
            outputStream -> CertificateAndKeyUtils.writePkcs12(outputStream, Map.of("httpca", httpCa.certAndKey), null, httpCa.password));

        final CertificateAndKeyUtils.CertificateInformation
            transport =
            new CertificateAndKeyUtils.CertificateInformation(new X500Principal("CN=" + getHostname()),
                Collections.singletonList(getIpAddress()),
                Collections.singletonList(getHostname()),
                Collections.emptyList());
        final CertificateAndKeyUtils.CAInfo transportCa = generateCA();
        fullyWriteFile(Paths.get(env.configFile().toAbsolutePath().toString(), "transportCa.p12"),
            outputStream -> CertificateAndKeyUtils.writePkcs12(outputStream,
                Map.of("transportca", transportCa.certAndKey),
                null,
                transportCa.password));

        CertificateAndKeyUtils.generateAndWriteSignedCertificates(Paths.get(env.configFile().toString(), "http.p12").normalize(),
            Collections.singletonList(http),
            httpCa);
        CertificateAndKeyUtils.generateAndWriteSignedCertificates(Paths.get(env.configFile().toString(), "transport.p12").normalize(),
            Collections.singletonList(transport),
            transportCa);
    }

    private void updateConfiguration(Environment env) throws Exception {
        final Path configurationFile = Paths.get(env.configFile().toString(), "elasticsearch.yml").normalize();
        Settings settings = Settings.builder()
            // These will be defaulting to true vbut for now, set them
            .put("xpack.security.enabled", true)
            .put("xpack.security.transport.ssl.enabled", true)
            .put("xpack.security.http.ssl.enabled", true)
            .put("xpack.security.transport.ssl.verification_mode", "certificate")
            .put("xpack.security.transport.ssl.keystore.path", "transport.p12")
            .put("xpack.security.transport.ssl.truststore.path", "transport.p12")
            .put("xpack.security.http.ssl.keystore.path", "http.p12")
            .put(env.settings())
            .build();
        XContentBuilder yaml = XContentFactory.yamlBuilder();
        yaml.startObject();
        settings.toXContent(yaml, ToXContent.EMPTY_PARAMS);
        yaml.endObject();
        appendConfigToFile(configurationFile, Strings.toString(yaml));
    }

    void appendConfigToFile(Path file, String config) throws Exception {
        assert file != null;

        if (Files.exists(file) != false) {
            Files.write(file, config.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);} else {
            throw new UserException(ExitCodes.IO_ERROR, "Output file '" + file + "' does not exist");
        }
    }
}
