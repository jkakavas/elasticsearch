/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.packaging.test;

import org.elasticsearch.common.Strings;
import org.elasticsearch.packaging.util.Archives;
import org.elasticsearch.packaging.util.Installation;
import org.elasticsearch.packaging.util.Shell;

import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.elasticsearch.packaging.util.Archives.ARCHIVE_OWNER;
import static org.elasticsearch.packaging.util.Archives.installArchive;
import static org.elasticsearch.packaging.util.Archives.verifyArchiveInstallation;
import static org.elasticsearch.packaging.util.FileMatcher.Fileness.Directory;
import static org.elasticsearch.packaging.util.FileMatcher.Fileness.File;
import static org.elasticsearch.packaging.util.FileMatcher.file;
import static org.elasticsearch.packaging.util.FileMatcher.p660;
import static org.elasticsearch.packaging.util.FileMatcher.p750;
import static org.elasticsearch.packaging.util.FileUtils.getCurrentVersion;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

public class EnrollmentProcessTests extends PackagingTestCase {
    private Installation firstNode;
    private static final Pattern PASSWORD_REGEX = Pattern.compile("Password for the (\\w+) user is: (.+)$", Pattern.MULTILINE);

    public void test10AutoFormCluster() throws Exception {
        firstNode = installArchive(sh, distribution(), getRootTempDir().resolve("elasticsearch-node1"), getCurrentVersion());
        verifyArchiveInstallation(firstNode, distribution());
        sh.getEnv().put("ES_JAVA_OPTS", "-Xms2g -Xmx2g");
        Shell.Result startFirstNode = awaitElasticsearchStartupWithResult(
            firstNode,
            Archives.startElasticsearchWithTty(firstNode, sh, null, false)
        );
        Map<String, String> usersAndPasswords = parseUsersAndPasswords(startFirstNode.stdout);
        assertThat(usersAndPasswords.size(), equalTo(2));
        assertThat(usersAndPasswords.containsKey("elastic"), is(true));
        verifySecurityAutoConfigured(firstNode);

        Shell.Result createTokenResult = firstNode.executables().createEnrollmentToken.run("-s node");
        assertThat(Strings.isNullOrEmpty(createTokenResult.stdout), is(false));
        final String enrollmentToken = createTokenResult.stdout;
        final Installation secondNode = installArchive(
            sh,
            distribution(),
            getRootTempDir().resolve("elasticsearch-node2"),
            getCurrentVersion()
        );
        Shell.Result startSecondNode = awaitElasticsearchStartupWithResult(
            secondNode,
            Archives.runElasticsearchStartCommand(secondNode, sh, null, List.of("--enrollment-token", enrollmentToken), false)
        );
        assertThat(startSecondNode.exitCode, is(0));
        Map<String, String> secondNodeUsersAndPasswords = parseUsersAndPasswords(startSecondNode.stdout);
        assertThat(secondNodeUsersAndPasswords.size(), equalTo(0));
        verifySecurityAutoConfigured(secondNode);
    }

    private Map<String, String> parseUsersAndPasswords(String output) {
        Matcher matcher = PASSWORD_REGEX.matcher(output);
        assertNotNull(matcher);
        Map<String, String> usersAndPasswords = new HashMap<>();
        while (matcher.find()) {
            usersAndPasswords.put(matcher.group(1), matcher.group(2));
        }
        return usersAndPasswords;
    }

    private static void verifySecurityAutoConfigured(Installation es) throws Exception {
        Optional<String> autoConfigDirName = getAutoConfigPathDir(es);
        assertThat(autoConfigDirName.isPresent(), is(true));
        assertThat(es.config(autoConfigDirName.get()), file(Directory, ARCHIVE_OWNER, ARCHIVE_OWNER, p750));
        Stream.of("http_keystore_local_node.p12", "http_ca.crt", "transport_keystore_all_nodes.p12")
            .forEach(file -> assertThat(es.config(autoConfigDirName.get()).resolve(file), file(File, ARCHIVE_OWNER, ARCHIVE_OWNER, p660)));
        List<String> configLines = Files.readAllLines(es.config("elasticsearch.yml"));

        assertThat(configLines, hasItem("xpack.security.enabled: true"));
        assertThat(configLines, hasItem("xpack.security.http.ssl.enabled: true"));
        assertThat(configLines, hasItem("xpack.security.transport.ssl.enabled: true"));

        assertThat(configLines, hasItem("xpack.security.enrollment.enabled: true"));
        assertThat(configLines, hasItem("xpack.security.transport.ssl.verification_mode: certificate"));
        assertThat(
            configLines,
            hasItem(
                "xpack.security.transport.ssl.keystore.path: "
                    + es.config(autoConfigDirName.get()).resolve("transport_keystore_all_nodes.p12")
            )
        );
        assertThat(
            configLines,
            hasItem(
                "xpack.security.transport.ssl.truststore.path: "
                    + es.config(autoConfigDirName.get()).resolve("transport_keystore_all_nodes.p12")
            )
        );
        assertThat(
            configLines,
            hasItem("xpack.security.http.ssl.keystore.path: " + es.config(autoConfigDirName.get()).resolve("http_keystore_local_node.p12"))
        );
        assertThat(configLines, hasItem("http.host: [_local_, _site_]"));
    }

    private static Optional<String> getAutoConfigPathDir(Installation es) {
        final Shell.Result lsResult = sh.run("find \"" + es.config + "\" -maxdepth 1 -type d -iname \"tls_auto_config_initial_node_*\"");
        assertNotNull(lsResult.stdout);
        return Arrays.stream(lsResult.stdout.split(System.lineSeparator())).findFirst();
    }
}
