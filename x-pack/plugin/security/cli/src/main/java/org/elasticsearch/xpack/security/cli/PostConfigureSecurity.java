/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.cli;

import joptsimple.OptionSet;
import org.apache.http.HttpHost;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.elasticsearch.cli.EnvironmentAwareCommand;
import org.elasticsearch.cli.Terminal;
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
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.env.Environment;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.io.InputStream;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

public class PostConfigureSecurity extends EnvironmentAwareCommand {

    PostConfigureSecurity() {
        super("setup passwords");
    }

    public static void main(String[] args) throws Exception {
        exit(new PostConfigureSecurity().main(args, Terminal.DEFAULT));
    }

    @Override protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {
        final SecureString password = generateElasticPassword();
        terminal.println(Terminal.Verbosity.NORMAL, " Elastic password will be set to: " + password.toString());
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
            // HttpAsyncClient has a RetryHandler but only in version 5.0
            waitForCluster(client, terminal, env, 10);
            setPassword(password, env);
        } catch (Exception e) {
            terminal.errorPrintln("Exception in execute");
        }
    }

    void waitForCluster(RestClient client, Terminal terminal, Environment env, int retriesLeft) throws Exception {
        try {
            final Request request = new Request("GET", "/_cluster/health");
            request.addParameter("wait_for_status", "yellow");
            request.addParameter("timeout", "5s");
            request.setOptions(addBootstrapCredentials(env));
            Response response = client.performRequest(request);
            Map<String, Object> clusterHealthResponse = entityAsMap(response);
            final String status = (String) clusterHealthResponse.get("status");
            if (status.equalsIgnoreCase("red")) {
                throw new IllegalStateException("Cluster red");
            }
        } catch (Exception e) {
            if (retriesLeft > 0) {
                terminal.println(Terminal.Verbosity.VERBOSE, "Error: " + e.getMessage() + " .Will retry " + retriesLeft + " more times");
                terminal.println(Terminal.Verbosity.VERBOSE, "waiting for 3 secs");
                Thread.sleep(3000);
                retriesLeft -= 1;
                waitForCluster(client, terminal, env, retriesLeft);
            } else {
                throw new IllegalStateException("Error after retries");
            }
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

    private SSLContext getHttpSslContext(Environment env, String keyStorePass) throws Exception {
        Path trustStorePath = Paths.get(env.configFile().toString(), "httpCa.p12").normalize();
        KeyStore truststore = KeyStore.getInstance("pkcs12");
        try (InputStream is = Files.newInputStream(trustStorePath)) {
            truststore.load(is, keyStorePass.toCharArray());
        }
        SSLContextBuilder sslBuilder = SSLContexts.custom().loadTrustMaterial(truststore, null);
        return sslBuilder.build();
    }

}
