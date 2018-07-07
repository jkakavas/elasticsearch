/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.cli;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.LoggingAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.xpack.sql.cli.command.ClearScreenCliCommand;
import org.elasticsearch.xpack.sql.cli.command.CliCommand;
import org.elasticsearch.xpack.sql.cli.command.CliCommands;
import org.elasticsearch.xpack.sql.cli.command.CliSession;
import org.elasticsearch.xpack.sql.cli.command.FetchSeparatorCliCommand;
import org.elasticsearch.xpack.sql.cli.command.FetchSizeCliCommand;
import org.elasticsearch.xpack.sql.cli.command.PrintLogoCommand;
import org.elasticsearch.xpack.sql.cli.command.ServerInfoCliCommand;
import org.elasticsearch.xpack.sql.cli.command.ServerQueryCliCommand;
import org.elasticsearch.xpack.sql.client.HttpClient;
import org.elasticsearch.xpack.sql.client.ClientException;
import org.elasticsearch.xpack.sql.client.ConnectionConfiguration;
import org.elasticsearch.xpack.sql.client.Version;
import org.jline.terminal.TerminalBuilder;
import java.io.IOException;
import java.net.ConnectException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.LogManager;

public class Cli extends LoggingAwareCommand {
    private final OptionSpec<String> keystoreLocation;
    private final OptionSpec<String> truststoreLocation;
    private final OptionSpec<String> keyLocation;
    private final OptionSpec<String> certLocation;
    private final OptionSpec<String> caLocations;
    private final OptionSpec<Boolean> checkOption;
    private final OptionSpec<String> connectionString;

    /**
     * Use this VM Options to run in IntelliJ or Eclipse:
     * -Dorg.jline.terminal.type=xterm-256color
     * -Dorg.jline.terminal.jna=false
     * -Dorg.jline.terminal.jansi=false
     * -Dorg.jline.terminal.exec=false
     * -Dorg.jline.terminal.dumb=true
     */
    public static void main(String[] args) throws Exception {
        final Cli cli = new Cli(new JLineTerminal(TerminalBuilder.builder().build(), true));
        configureJLineLogging();
        int status = cli.main(args, Terminal.DEFAULT);
        if (status != ExitCodes.OK) {
            exit(status);
        }
    }

    private static void configureJLineLogging() {
        try {
            /* Initialize the logger from the a properties file we bundle. This makes sure
             * we get useful error messages from jLine. */
            LogManager.getLogManager().readConfiguration(Cli.class.getResourceAsStream("/logging.properties"));
        } catch (IOException ex) {
            throw new RuntimeException("cannot setup logging", ex);
        }
    }

    private final CliTerminal cliTerminal;

    /**
     * Build the CLI.
     */
    public Cli(CliTerminal cliTerminal) {
        super("Elasticsearch SQL CLI");
        this.cliTerminal = cliTerminal;
        parser.acceptsAll(Arrays.asList("d", "debug"), "Enable debug logging");
        this.keystoreLocation = parser.acceptsAll(
                    Arrays.asList("k", "keystore_location"),
                    "Location of a keystore to use when setting up SSL. "
                    + "If specified then the CLI will prompt for a keystore password. "
                    + "If specified when the uri isn't https then an error is thrown.")
                .withRequiredArg().ofType(String.class);
        this.truststoreLocation = parser.acceptsAll(
            Arrays.asList("k", "keystore_location"),
            "Location of a keystore to use when setting up SSL. "
                + "If specified then the CLI will prompt for a keystore password. "
                + "If specified when the uri isn't https then an error is thrown.")
            .withRequiredArg().ofType(String.class);
        this.keyLocation = parser.accepts("key", "Location of a key file to use when setting up SSL. " +
            "This key will be used for SSL client authentication. If specified then the CLI will prompt for the key password.")
            .withRequiredArg().ofType(String.class);
        this.certLocation = parser.accepts("certificate", "Location of a certificate file to use when" +
            "setting up SSL. This certificate will be used for SSL client authentication.")
            .withRequiredArg().ofType(String.class);
        this.caLocations = parser.accepts("cacerts", "Location of certificate authorities file(s) to use when" +
            "setting up SSL. These CA certificates will be used to validate the server certificate when an https uri is used." +
            "Multiple comma separated locations can be used.")
            .withRequiredArg().ofType(String.class);
        this.checkOption = parser.acceptsAll(Arrays.asList("c", "check"),
                "Enable initial connection check on startup")
                .withRequiredArg().ofType(Boolean.class)
                .defaultsTo(Boolean.parseBoolean(System.getProperty("cli.check", "true")));
        this.connectionString = parser.nonOptions("uri");
    }

    @Override
    protected void execute(org.elasticsearch.cli.Terminal terminal, OptionSet options) throws Exception {
        boolean debug = options.has("d") || options.has("debug");
        boolean checkConnection = checkOption.value(options);
        List<String> args = connectionString.values(options);
        if (args.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "expecting a single uri");
        }
        String uri = args.size() == 1 ? args.get(0) : null;
        List<String> keyStoreArgs = keystoreLocation.values(options);
        List<String> trustStoreArgs = truststoreLocation.values(options);
        List<String> keyArgs = keyLocation.values(options);
        List<String> certArgs = certLocation.values(options);
        List<String> caArgs = caLocations.values(options);
        if (keyArgs.isEmpty() == false && keyStoreArgs.isEmpty() == false) {
            throw new UserException(ExitCodes.USAGE, "keystores can't be used at the same time as keys");
        }
        if (keyArgs.isEmpty() == false && certArgs.isEmpty()) {
            throw new UserException(ExitCodes.USAGE, "certificate must be specified when key is used");
        }
        if (caArgs.isEmpty() == false && trustStoreArgs.isEmpty() == false) {
            throw new UserException(ExitCodes.USAGE, "truststore can't be used at the same time as ca certificates");
        }
        if (keyStoreArgs.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "expecting a single keystore file");
        }
        if (trustStoreArgs.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "expecting a single truststore file");
        }
        if (keyArgs.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "expecting a single key file");
        }
        if (certArgs.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "expecting a single certificate file");
        }
        if (caArgs.size() > 1) {
            throw new UserException(ExitCodes.USAGE, "please specify multiple ca certificates as a comma separated string");
        }
        String keystoreLocationValue = keyStoreArgs.size() == 1 ? keyStoreArgs.get(0) : null;
        String truststoreLocationValue = trustStoreArgs.size() == 1 ? trustStoreArgs.get(0) : null;
        String keyLocationValue = keyArgs.size() == 1 ? keyArgs.get(0) : null;
        String certLocationValue = certArgs.size() == 1 ? certArgs.get(0) : null;
        String caLocationValue = caArgs.size() == 1 ? caArgs.get(0) : null;
        execute(uri, debug, keystoreLocationValue, truststoreLocationValue, keyLocationValue, certLocationValue, caLocationValue,
            checkConnection);
    }

    private void execute(String uri, boolean debug, String keystoreLocation, String truststoreLocation, String keyLocationValue,
                         String certLocationValue, String caLocationValue, boolean checkConnection) throws Exception {
        CliCommand cliCommand = new CliCommands(
                new PrintLogoCommand(),
                new ClearScreenCliCommand(),
                new FetchSizeCliCommand(),
                new FetchSeparatorCliCommand(),
                new ServerInfoCliCommand(),
                new ServerQueryCliCommand()
        );
        try {
            ConnectionBuilder connectionBuilder = new ConnectionBuilder(cliTerminal);
            //
            ConnectionConfiguration con = connectionBuilder.buildConnection(uri, keystoreLocation, truststoreLocation, keyLocationValue,
                certLocationValue, caLocationValue);
            CliSession cliSession = new CliSession(new HttpClient(con));
            cliSession.setDebug(debug);
            if (checkConnection) {
                checkConnection(cliSession, cliTerminal, con);
            }
            new CliRepl(cliTerminal, cliSession, cliCommand).execute();
        } finally {
            cliTerminal.close();
        }
    }

    private void checkConnection(CliSession cliSession, CliTerminal cliTerminal, ConnectionConfiguration con) throws UserException {
        try {
            cliSession.checkConnection();
        } catch (ClientException ex) {
            if (cliSession.isDebug()) {
                cliTerminal.error("Client Exception", ex.getMessage());
                cliTerminal.println();
                cliTerminal.printStackTrace(ex);
                cliTerminal.flush();
            }
            if (ex.getCause() != null && ex.getCause() instanceof ConnectException) {
                // Most likely Elasticsearch is not running
                throw new UserException(ExitCodes.IO_ERROR,
                        "Cannot connect to the server " + con.connectionString() + " - " + ex.getCause().getMessage());
            } else {
                // Most likely we connected to something other than Elasticsearch
                throw new UserException(ExitCodes.DATA_ERROR,
                        "Cannot communicate with the server " + con.connectionString() +
                                ". This version of CLI only works with Elasticsearch version " + Version.CURRENT.toString());
            }
        }
    }
}
