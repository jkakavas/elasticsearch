/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.cli;

import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.common.CheckedSupplier;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.network.InetAddresses;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.env.Environment;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.common.socket.SocketAccess;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.core.ssl.SSLConfiguration;
import org.elasticsearch.xpack.core.ssl.SSLService;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.PrivilegedAction;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PORT;
import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PUBLISH_HOST;
import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PUBLISH_PORT;

/**
 * A simple http client for usage in command line tools. This client only uses internal jdk classes and does
 * not rely on an external http libraries.
 */
public class FingerprintTrustingHttpsClient {

    /**
     * Timeout HTTP(s) reads after 35 seconds.
     * The default timeout for discovering a master is 30s, and we want to be longer than this, otherwise a querying a disconnected node
     * will trigger as client side timeout rather than giving clear error details.
     */
    private static final int READ_TIMEOUT = 35 * 1000;

    private final String fingerprint;

    public FingerprintTrustingHttpsClient(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    @SuppressForbidden(reason = "We call connect in doPrivileged and provide SocketPermission")
    public HttpResponse execute(String method, URL url, SecureString apiKey,
        CheckedSupplier<String, Exception> requestBodySupplier,
        CheckedFunction<InputStream, HttpResponse.HttpResponseBuilder, Exception> responseHandler) throws Exception {

        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                matchesCertFingerprint(chain[chain.length-1]);
            }

            @Override public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{tm}, null);
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setRequestMethod(method);
        conn.setReadTimeout(READ_TIMEOUT);
        // Add basic-auth header

        conn.setRequestProperty("Authorization", "ApiKey "+apiKey);
        conn.setRequestProperty("Content-Type", XContentType.JSON.mediaType());
        String bodyString = requestBodySupplier.get();
        conn.setDoOutput(bodyString != null); // set true if we are sending a body
        SocketAccess.doPrivileged(conn::connect);
        if (bodyString != null) {
            try (OutputStream out = conn.getOutputStream()) {
                out.write(bodyString.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                Releasables.closeWhileHandlingException(conn::disconnect);
                throw e;
            }
        }
        // this throws IOException if there is a network problem
        final int responseCode = conn.getResponseCode();
        HttpResponse.HttpResponseBuilder responseBuilder = null;
        try (InputStream inputStream = conn.getInputStream()) {
            responseBuilder = responseHandler.apply(inputStream);
        } catch (IOException e) {
            // this IOException is if the HTTP response code is 'BAD' (>= 400)
            try (InputStream errorStream = conn.getErrorStream()) {
                responseBuilder = responseHandler.apply(errorStream);
            }
        } finally {
            Releasables.closeWhileHandlingException(conn::disconnect);
        }
        responseBuilder.withHttpStatus(responseCode);
        return responseBuilder.build();
    }

    private void matchesCertFingerprint(X509Certificate cert) throws CertificateException {
        MessageDigest sha256 = MessageDigests.sha256();
        sha256.update(cert.getEncoded());
        if (MessageDigests.toHexString(sha256.digest()).equals(fingerprint) == false ) {
            throw new CertificateException();
        }
    }
}
