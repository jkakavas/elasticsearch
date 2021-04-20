/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.bootstrap;

import joptsimple.OptionSet;
import org.apache.http.HttpHost;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.elasticsearch.cli.EnvironmentAwareCommand;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.Randomness;
import org.elasticsearch.common.Strings;

import org.elasticsearch.common.settings.KeyStoreWrapper;
import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.env.Environment;

import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.bootstrap.CertificateAndKeyUtils.fullyWriteFile;
import static org.elasticsearch.bootstrap.CertificateAndKeyUtils.generateCA;
import static org.elasticsearch.bootstrap.CertificateAndKeyUtils.getHostname;
import static org.elasticsearch.bootstrap.CertificateAndKeyUtils.getIpAddress;

public class ElasticsearchHelper extends EnvironmentAwareCommand {
    ElasticsearchHelper() {
        super("Starts Elasticsearch");
    }

    public static void main(String[] args) throws Exception {
        ElasticsearchHelper helper = new ElasticsearchHelper();
        int status = main(helper, args, Terminal.DEFAULT);
        if (status != ExitCodes.OK) {
            exit(status);
        }
    }

    static int main(ElasticsearchHelper helper, String[] args, Terminal terminal) throws Exception {
        return helper.main(args, terminal);
    }

    @Override protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {
        final SecureString password = generateElasticPassword();
        generateKeysAndCertificates(env);
        updateConfiguration(env);
        terminal.println(Terminal.Verbosity.NORMAL, " Elastic password will be set to: " + password.toString());
        startElasticsearch(new String[] {});
        final SSLContext sslContext = getHttpSslContext(env, "password");
        try (
            RestClient client = RestClient.builder(new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override public HttpAsyncClientBuilder customizeHttpClient(
                        HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext);
                    }
                })
                .build()) {
            final Request request = new Request("GET", "/_cluster/health");
            request.addParameter("wait_for_status", "yellow");
            request.addParameter("timeout", "5s");
            request.setOptions(addBootstrapCredentials(env));
            Response response = client.performRequest(request);
            Map<String, Object> clusterHealthResponse = entityAsMap(response);
            final String status = (String) clusterHealthResponse.get("status");
            if (status.equalsIgnoreCase("yellow") || status.equalsIgnoreCase("green")) {
                setPassword(password, env);
            } else {
                System.out.println("RED");
            }
        } catch (Exception e) {
            //ERROR HANDLING
            e.printStackTrace();
        }
    }

    private static SecureString generateElasticPassword() {
        final char[] allowedChars = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*-_=+?").toCharArray();
        SecureRandom random = Randomness.createSecure();
        int passwordLength = 8;
        char[] characters = new char[passwordLength];
        for (int i = 0; i < 8; ++i) {
            characters[i] = allowedChars[random.nextInt(allowedChars.length)];
        }
        return new SecureString(characters);
    }

    private void generateKeysAndCertificates(Environment env) throws Exception {
        final CertificateAndKeyUtils.CertificateInformation
            http =
            new CertificateAndKeyUtils.CertificateInformation(new X500Principal("CN=" + getHostname()),
                Collections.singletonList(getIpAddress()),
                List.of(getHostname(), "localhost"),
                Collections.emptyList());
        final CertificateAndKeyUtils.CAInfo httpCa = generateCA();
        fullyWriteFile(Paths.get(env.configFile().toAbsolutePath().toString(), "httpCa.p12"),
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

    private void startElasticsearch(String[] args) throws Exception {
        Elasticsearch.main(args);
    }

    private void setPassword(SecureString password, Environment env) throws Exception {
        final SSLContext sslContext = getHttpSslContext(env, "password");
        try (
            password;
            RestClient client = RestClient.builder(new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override public HttpAsyncClientBuilder customizeHttpClient(
                        HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext);
                    }
                })
                .build()) {
            final Request request = new Request("PUT", "/_security/user/elastic/_password");
            XContentBuilder xContentBuilder = JsonXContent.contentBuilder();
            xContentBuilder.startObject().field("password", password.toString()).endObject();
            request.setJsonEntity(Strings.toString(xContentBuilder));
            request.setOptions(addBootstrapCredentials(env));
            client.performRequest(request);
        } catch (Exception e) {
            //ERROR HANDLING
            e.printStackTrace();
        }
    }

    private static RequestOptions addBootstrapCredentials(Environment environment) throws Exception {
        KeyStoreWrapper keyStoreWrapper = KeyStoreWrapper.load(environment.configFile());
        keyStoreWrapper.decrypt(new char[0]);
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(environment.settings(), true);
        if (settingsBuilder.getSecureSettings() == null) {
            settingsBuilder.setSecureSettings(keyStoreWrapper);
        }
        Settings settings = settingsBuilder.build();
        final SecureString bootstrapPassword = SecureSetting.secureString("bootstrap.password", KeyStoreWrapper.SEED_SETTING).get(settings);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.addHeader("Authorization", basicAuthHeaderValue("elastic", bootstrapPassword));
        return options.build();
    }

    /**
     * Convert the entity from a {@link Response} into a map of maps.
     */
    private static Map<String, Object> entityAsMap(Response response) throws IOException {
        XContentType xContentType = XContentType.fromMediaType(response.getEntity().getContentType().getValue());
        // EMPTY and THROW are fine here because `.map` doesn't use named x content or deprecation
        try (
            XContentParser parser = xContentType.xContent()
                .createParser(NamedXContentRegistry.EMPTY,
                    DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                    response.getEntity().getContent())) {
            return parser.map();
        }
    }

    private static String basicAuthHeaderValue(String username, SecureString passwd) {
        CharBuffer chars = CharBuffer.allocate(username.length() + passwd.length() + 1);
        byte[] charBytes = null;
        try {
            chars.put(username).put(':').put(passwd.getChars());
            charBytes = CharArrays.toUtf8Bytes(chars.array());
            String basicToken = Base64.getEncoder().encodeToString(charBytes);
            return "Basic " + basicToken;
        } finally {
            Arrays.fill(chars.array(), (char) 0);
            if (charBytes != null) {
                Arrays.fill(charBytes, (byte) 0);
            }
        }
    }

    private SSLContext getHttpSslContext(Environment env, String keyStorePass) throws Exception {
        Path trustStorePath = Paths.get(env.configFile().toString(), "httpCa.p12").normalize();
        KeyStore truststore = KeyStore.getInstance("pkcs12");
        try (InputStream is = Files.newInputStream(trustStorePath)) {
            truststore.load(is, keyStorePass.toCharArray());
        }
        SSLContextBuilder sslBuilder = SSLContexts.custom().loadTrustMaterial(truststore, null);
        return sslBuilder.build();
    }

    void appendConfigToFile(Path file, String config) throws Exception {
        assert file != null;

        if (Files.exists(file) == false) {
            throw new UserException(ExitCodes.IO_ERROR, "Output file '" + file + "' does not exist");
        }
        Files.write(file, config.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
    }

}
