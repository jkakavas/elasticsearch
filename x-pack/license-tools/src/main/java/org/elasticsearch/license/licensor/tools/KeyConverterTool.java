package org.elasticsearch.license.licensor.tools;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.LoggingAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.license.CryptUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

public class KeyConverterTool extends LoggingAwareCommand {

    private final OptionSpec<String> oldFormatKey;
    private final OptionSpec<String> newFormatKey;

    public KeyConverterTool() {
        super("Converts a pre 6.4 signer private key to the new format");
        this.oldFormatKey = parser.accepts("oldFormatKey", "old format private key path")
            .withRequiredArg().required();
        this.newFormatKey = parser.accepts("newFormatKey", "new format private key path")
            .withRequiredArg().required();
    }

    public static void main(String[] args) throws Exception {
        exit(new KeyConverterTool().main(args, Terminal.DEFAULT));
    }

    @Override
    protected void printAdditionalHelp(Terminal terminal) {
        terminal.println("This tool converts a license signing key that was used with old versions");
        terminal.println("of the license signer CLI tool, to the new format that is used by new");
        terminal.println("new versions ( after 6.4 ) of the license signer CLI Tool.");
        terminal.println("");
    }

    @Override
    protected void execute(Terminal terminal, OptionSet options) throws Exception {
        Path oldFormatKeyPath = parsePath(oldFormatKey.value(options));
        Path newFormatKeyPath = parsePath(newFormatKey.value(options));
        if (Files.exists(newFormatKeyPath)) {
            throw new UserException(ExitCodes.USAGE, newFormatKeyPath + " already exists");
        }
        if (Files.exists(oldFormatKeyPath) == false || Files.isRegularFile(oldFormatKeyPath) == false) {
            throw new UserException(ExitCodes.USAGE, oldFormatKeyPath + " is not available or is not a file");
        }
        PrivateKey key = CryptUtils.readEncryptedPrivateKey(Files.readAllBytes(oldFormatKeyPath), "elasticsearch-license".toCharArray(),
            true);
        Files.write(newFormatKeyPath, CryptUtils.writeEncryptedPrivateKey(key));
    }

    @SuppressForbidden(reason = "Parsing command line path")
    private static Path parsePath(String path) {
        return PathUtils.get(path);
    }
}
