/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.cli;

import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.SuppressForbidden;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.xpack.sql.client.ConnectionConfiguration;
import org.elasticsearch.xpack.sql.client.SslConfig;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import static org.elasticsearch.xpack.sql.client.UriUtils.parseURI;
import static org.elasticsearch.xpack.sql.client.UriUtils.removeQuery;

/**
 * Connection Builder. Can interactively ask users for the password if it is not provided
 */
public class ConnectionBuilder {
    public static String DEFAULT_CONNECTION_STRING = "http://localhost:9200/";
    public static URI DEFAULT_URI = URI.create(DEFAULT_CONNECTION_STRING);

    private CliTerminal cliTerminal;

    public ConnectionBuilder(CliTerminal cliTerminal) {
        this.cliTerminal = cliTerminal;
    }

    /**
     * Build the connection.
     *
     * @param connectionStringArg the connection string to connect to
     * @param keystoreLocation    the location of the keystore to configure. If null then use the system keystore.
     * @throws UserException if there is a problem with the information provided by the user
     */
    public ConnectionConfiguration buildConnection(String connectionStringArg, String keystoreLocation, String truststoreLocation,
                                                   String keyLocation, String certLocation, String caLocation) throws UserException {
        final URI uri;
        final String connectionString;
        Properties properties = new Properties();
        String user = null;
        String password = null;
        if (connectionStringArg != null) {
            connectionString = connectionStringArg;
            uri = removeQuery(parseURI(connectionString, DEFAULT_URI), connectionString, DEFAULT_URI);
            user = uri.getUserInfo();
            if (user != null) {
                int colonIndex = user.indexOf(':');
                if (colonIndex >= 0) {
                    password = user.substring(colonIndex + 1);
                    user = user.substring(0, colonIndex);
                }
            }
        } else {
            uri = DEFAULT_URI;
            connectionString = DEFAULT_CONNECTION_STRING;
        }

        if (keystoreLocation != null) {
            if (false == "https".equals(uri.getScheme())) {
                throw new UserException(ExitCodes.USAGE, "keystore file specified without https");
            }
            Path p = getFilePath(keystoreLocation);
            checkIfExists("keystore file", p);
            String keystorePassword = cliTerminal.readPassword("keystore password: ");

            properties.put(SslConfig.SSL_KEYSTORE_LOCATION, keystoreLocation);
            properties.put(SslConfig.SSL_KEYSTORE_PASS, keystorePassword);
            if (truststoreLocation != null) {
                String truststorePassword = cliTerminal.readPassword("keystore password: ");
                properties.put(SslConfig.SSL_TRUSTSTORE_LOCATION, truststoreLocation);
                properties.put(SslConfig.SSL_TRUSTSTORE_PASS, truststorePassword);
            } else {
                // If truststore is not explicitly configured, use the keystore as truststore as well.
                properties.put(SslConfig.SSL_TRUSTSTORE_LOCATION, keystoreLocation);
                properties.put(SslConfig.SSL_TRUSTSTORE_PASS, keystorePassword);
            }
        } else if (keyLocation != null) {
            if (false == "https".equals(uri.getScheme())) {
                throw new UserException(ExitCodes.USAGE, "key file specified without https");
            }
            Path keyPath = getFilePath(keyLocation);
            checkIfExists("key file", keyPath);
            Path certPath = getFilePath(certLocation);
            checkIfExists("key file", certPath);
            properties.put(SslConfig.SSL_KEY, keyLocation);
            properties.put(SslConfig.SSL_CERTIFICATE, certLocation);
            if (caLocation != null) {
                properties.put(SslConfig.SSL_CERTIFICATE_AUTHORITIES, caLocation);
            } else if (truststoreLocation != null) {
                String truststorePassword = cliTerminal.readPassword("keystore password: ");
                properties.put(SslConfig.SSL_TRUSTSTORE_LOCATION, truststoreLocation);
                properties.put(SslConfig.SSL_TRUSTSTORE_PASS, truststorePassword);
            }
        }

        if ("https".equals(uri.getScheme())) {
            properties.put("ssl", "true");
        }

        if (user != null) {
            if (password == null) {
                password = cliTerminal.readPassword("password: ");
            }
            properties.setProperty(ConnectionConfiguration.AUTH_USER, user);
            properties.setProperty(ConnectionConfiguration.AUTH_PASS, password);
        }

        return newConnectionConfiguration(uri, connectionString, properties);
    }

    @SuppressForbidden(reason = "cli application shouldn't depend on ES")
    private Path getFilePath(String location) {
        return Paths.get(location);
    }

    protected ConnectionConfiguration newConnectionConfiguration(URI uri, String connectionString, Properties properties) {
        return new ConnectionConfiguration(uri, connectionString, properties);
    }

    protected void checkIfExists(String name, Path p) throws UserException {
        if (false == Files.exists(p)) {
            throw new UserException(ExitCodes.USAGE, name + " [" + p + "] doesn't exist");
         }
         if (false == Files.isRegularFile(p)) {
             throw new UserException(ExitCodes.USAGE, name + " [" + p + "] isn't a regular file");
         }
    }

}
