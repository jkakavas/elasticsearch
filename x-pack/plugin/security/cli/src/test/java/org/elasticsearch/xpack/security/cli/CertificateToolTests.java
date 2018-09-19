/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.cli;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.elasticsearch.cli.MockTerminal;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.CollectionUtils;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.TestEnvironment;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.SecuritySettingsSourceField;
import org.elasticsearch.test.TestMatchers;
import org.elasticsearch.xpack.security.cli.CertificateTool.CAInfo;
import org.elasticsearch.xpack.security.cli.CertificateTool.CertificateAuthorityCommand;
import org.elasticsearch.xpack.security.cli.CertificateTool.CertificateCommand;
import org.elasticsearch.xpack.security.cli.CertificateTool.CertificateInformation;
import org.elasticsearch.xpack.security.cli.CertificateTool.GenerateCertificateCommand;
import org.elasticsearch.xpack.security.cli.CertificateTool.Name;
import org.elasticsearch.xpack.core.ssl.CertParsingUtils;
import org.elasticsearch.xpack.core.ssl.PemUtils;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.BeforeClass;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.nullValue;

/**
 * Unit tests for the tool used to simplify SSL certificate generation
 */
public class CertificateToolTests extends ESTestCase {

    private FileSystem jimfs;
    private static final String CN_OID = "2.5.4.3";

    private Path initTempDir() throws Exception {
        Configuration conf = Configuration.unix().toBuilder().setAttributeViews("posix").build();
        jimfs = Jimfs.newFileSystem(conf);
        Path tempDir = jimfs.getPath("temp");
        IOUtils.rm(tempDir);
        Files.createDirectories(tempDir);
        return tempDir;
    }

    @BeforeClass
    public static void chechFipsJvm() {
        assumeFalse("Can't run in a FIPS JVM, depends on Non FIPS BouncyCastle", inFipsJvm());
    }

    @After
    public void tearDown() throws Exception {
        IOUtils.close(jimfs);
        super.tearDown();
    }

    public void testOutputDirectory() throws Exception {
        Path outputDir = createTempDir();
        Path outputFile = outputDir.resolve("certs.zip");
        MockTerminal terminal = new MockTerminal();

        // test with a user provided file
        Path resolvedOutputFile = CertificateCommand.resolveOutputPath(terminal, outputFile.toString(), "something");
        assertEquals(outputFile, resolvedOutputFile);
        assertTrue(terminal.getOutput().isEmpty());

        // test without a user provided file, with user input (prompted)
        Path userPromptedOutputFile = outputDir.resolve("csr");
        assertFalse(Files.exists(userPromptedOutputFile));
        terminal.addTextInput(userPromptedOutputFile.toString());
        resolvedOutputFile = CertificateCommand.resolveOutputPath(terminal, (String) null, "default.zip");
        assertEquals(userPromptedOutputFile, resolvedOutputFile);
        assertTrue(terminal.getOutput().isEmpty());

        // test with empty user input
        String defaultFilename = randomAlphaOfLengthBetween(1, 10);
        Path expectedDefaultPath = resolvePath(defaultFilename);
        terminal.addTextInput("");
        resolvedOutputFile = CertificateCommand.resolveOutputPath(terminal, (String) null, defaultFilename);
        assertEquals(expectedDefaultPath, resolvedOutputFile);
        assertTrue(terminal.getOutput().isEmpty());
    }

    public void testPromptingForInstanceInformation() throws Exception {
        final int numberOfInstances = scaledRandomIntBetween(1, 12);
        Map<String, Map<String, String>> instanceInput = new HashMap<>(numberOfInstances);
        for (int i = 0; i < numberOfInstances; i++) {
            final String name;
            while (true) {
                String randomName = getValidRandomInstanceName();
                if (instanceInput.containsKey(randomName) == false) {
                    name = randomName;
                    break;
                }
            }
            Map<String, String> instanceInfo = new HashMap<>();
            instanceInput.put(name, instanceInfo);
            instanceInfo.put("ip", randomFrom("127.0.0.1", "::1", "192.168.1.1,::1", ""));
            instanceInfo.put("dns", randomFrom("localhost", "localhost.localdomain", "localhost,myhost", ""));
            logger.info("instance [{}] name [{}] [{}]", i, name, instanceInfo);
        }

        int count = 0;
        MockTerminal terminal = new MockTerminal();
        for (Entry<String, Map<String, String>> entry : instanceInput.entrySet()) {
            terminal.addTextInput(entry.getKey());
            terminal.addTextInput("");
            terminal.addTextInput(entry.getValue().get("ip"));
            terminal.addTextInput(entry.getValue().get("dns"));
            count++;
            if (count == numberOfInstances) {
                terminal.addTextInput("n");
            } else {
                terminal.addTextInput("y");
            }
        }

        Collection<CertificateInformation> certInfos = CertificateCommand.readMultipleCertificateInformation(terminal);
        logger.info("certificate tool output:\n{}", terminal.getOutput());
        assertEquals(numberOfInstances, certInfos.size());
        for (CertificateInformation certInfo : certInfos) {
            String name = certInfo.name.originalName;
            Map<String, String> instanceInfo = instanceInput.get(name);
            assertNotNull("did not find map for " + name, instanceInfo);
            List<String> expectedIps = Arrays.asList(Strings.commaDelimitedListToStringArray(instanceInfo.get("ip")));
            List<String> expectedDns = Arrays.asList(Strings.commaDelimitedListToStringArray(instanceInfo.get("dns")));
            assertEquals(expectedIps, certInfo.ipAddresses);
            assertEquals(expectedDns, certInfo.dnsNames);
            instanceInput.remove(name);
        }
        assertEquals(0, instanceInput.size());
        final String output = terminal.getOutput();
        assertTrue("Output: " + output, output.isEmpty());
    }

    public void testParsingFile() throws Exception {
        Path tempDir = initTempDir();
        Path instanceFile = writeInstancesTo(tempDir.resolve("instances.yml"));
        Collection<CertificateInformation> certInfos = CertificateTool.parseFile(instanceFile);
        assertEquals(4, certInfos.size());

        Map<String, CertificateInformation> certInfosMap =
                certInfos.stream().collect(Collectors.toMap((c) -> c.name.originalName, Function.identity()));
        CertificateInformation certInfo = certInfosMap.get("node1");
        assertEquals(Collections.singletonList("127.0.0.1"), certInfo.ipAddresses);
        assertEquals(Collections.singletonList("localhost"), certInfo.dnsNames);
        assertEquals(Collections.emptyList(), certInfo.commonNames);
        assertEquals("node1", certInfo.name.filename);

        certInfo = certInfosMap.get("node2");
        assertEquals(Collections.singletonList("::1"), certInfo.ipAddresses);
        assertEquals(Collections.emptyList(), certInfo.dnsNames);
        assertEquals(Collections.singletonList("node2.elasticsearch"), certInfo.commonNames);
        assertEquals("node2", certInfo.name.filename);

        certInfo = certInfosMap.get("node3");
        assertEquals(Collections.emptyList(), certInfo.ipAddresses);
        assertEquals(Collections.emptyList(), certInfo.dnsNames);
        assertEquals(Collections.emptyList(), certInfo.commonNames);
        assertEquals("node3", certInfo.name.filename);

        certInfo = certInfosMap.get("CN=different value");
        assertEquals(Collections.emptyList(), certInfo.ipAddresses);
        assertEquals(Collections.singletonList("node4.mydomain.com"), certInfo.dnsNames);
        assertEquals(Collections.emptyList(), certInfo.commonNames);
        assertEquals("different file", certInfo.name.filename);
    }

    public void testParsingFileWithInvalidDetails() throws Exception {
        Path tempDir = initTempDir();
        Path instanceFile = writeInvalidInstanceInformation(tempDir.resolve("instances-invalid.yml"));
        final MockTerminal terminal = new MockTerminal();
        final UserException exception = expectThrows(UserException.class,
                () -> CertificateTool.parseAndValidateFile(terminal, instanceFile));
        assertThat(exception.getMessage(), containsString("invalid configuration"));
        assertThat(exception.getMessage(), containsString(instanceFile.toString()));
        assertThat(terminal.getOutput(), containsString("THIS=not a,valid DN"));
        assertThat(terminal.getOutput(), containsString("could not be converted to a valid DN"));
    }

    public void testGeneratingCsr() throws Exception {
        Path tempDir = initTempDir();
        Path outputFile = tempDir.resolve("out.zip");
        Path instanceFile = writeInstancesTo(tempDir.resolve("instances.yml"));
        Collection<CertificateInformation> certInfos = CertificateTool.parseFile(instanceFile);
        assertEquals(4, certInfos.size());

        assertFalse(Files.exists(outputFile));
        int keySize = randomFrom(1024, 2048);

        new CertificateTool.SigningRequestCommand().generateAndWriteCsrs(outputFile, keySize, certInfos);
        assertTrue(Files.exists(outputFile));

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(outputFile);
        assertTrue(perms.toString(), perms.contains(PosixFilePermission.OWNER_READ));
        assertTrue(perms.toString(), perms.contains(PosixFilePermission.OWNER_WRITE));
        assertEquals(perms.toString(), 2, perms.size());

        FileSystem fileSystem = FileSystems.newFileSystem(new URI("jar:" + outputFile.toUri()), Collections.emptyMap());
        Path zipRoot = fileSystem.getPath("/");

        assertFalse(Files.exists(zipRoot.resolve("ca")));
        for (CertificateInformation certInfo : certInfos) {
            String filename = certInfo.name.filename;
            assertTrue(Files.exists(zipRoot.resolve(filename)));
            final Path csr = zipRoot.resolve(filename + "/" + filename + ".csr");
            assertTrue(Files.exists(csr));
            assertTrue(Files.exists(zipRoot.resolve(filename + "/" + filename + ".key")));
            PKCS10CertificationRequest request = readCertificateRequest(csr);
            assertEquals(certInfo.name.x500Principal.getName(), request.getSubject().toString());
            Attribute[] extensionsReq = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (certInfo.ipAddresses.size() > 0 || certInfo.dnsNames.size() > 0) {
                assertEquals(1, extensionsReq.length);
                Extensions extensions = Extensions.getInstance(extensionsReq[0].getAttributeValues()[0]);
                GeneralNames subjAltNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                assertSubjAltNames(subjAltNames, certInfo);
            } else {
                assertEquals(0, extensionsReq.length);
            }
        }
    }

    public void testGeneratingSignedPemCertificates() throws Exception {
        Path tempDir = initTempDir();
        Path outputFile = tempDir.resolve("out.zip");
        Path instanceFile = writeInstancesTo(tempDir.resolve("instances.yml"));
        Collection<CertificateInformation> certInfos = CertificateTool.parseFile(instanceFile);
        assertEquals(4, certInfos.size());

        int keySize = randomFrom(1024, 2048);
        int days = randomIntBetween(1, 1024);

        KeyPair keyPair = CertGenUtils.generateKeyPair(keySize);
        X509Certificate caCert = CertGenUtils.generateCACertificate(new X500Principal("CN=test ca"), keyPair, days);

        final boolean generatedCa = randomBoolean();
        final boolean keepCaKey = generatedCa && randomBoolean();
        final String keyPassword = randomBoolean() ? SecuritySettingsSourceField.TEST_PASSWORD : null;

        assertFalse(Files.exists(outputFile));
        CAInfo caInfo = new CAInfo(caCert, keyPair.getPrivate(), generatedCa, keyPassword == null ? null : keyPassword.toCharArray());
        final GenerateCertificateCommand command = new GenerateCertificateCommand();
        List<String> args = CollectionUtils.arrayAsArrayList("-keysize", String.valueOf(keySize), "-days", String.valueOf(days), "-pem");
        if (keyPassword != null) {
            args.add("-pass");
            args.add(keyPassword);
        }
        if (keepCaKey) {
            args.add("-keep-ca-key");
        }
        final OptionSet options = command.getParser().parse(Strings.toStringArray(args));

        command.generateAndWriteSignedCertificates(outputFile, true, options, certInfos, caInfo, null);
        assertTrue(Files.exists(outputFile));

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(outputFile);
        assertTrue(perms.toString(), perms.contains(PosixFilePermission.OWNER_READ));
        assertTrue(perms.toString(), perms.contains(PosixFilePermission.OWNER_WRITE));
        assertEquals(perms.toString(), 2, perms.size());

        FileSystem fileSystem = FileSystems.newFileSystem(new URI("jar:" + outputFile.toUri()), Collections.emptyMap());
        Path zipRoot = fileSystem.getPath("/");

        if (generatedCa) {
            assertTrue(Files.exists(zipRoot.resolve("ca")));
            assertTrue(Files.exists(zipRoot.resolve("ca").resolve("ca.crt")));
            // check the CA cert
            try (InputStream input = Files.newInputStream(zipRoot.resolve("ca").resolve("ca.crt"))) {
                X509Certificate parsedCaCert = readX509Certificate(input);
                assertThat(parsedCaCert.getSubjectX500Principal().getName(), containsString("test ca"));
                assertEquals(caCert, parsedCaCert);
                long daysBetween = getDurationInDays(caCert);
                assertEquals(days, (int) daysBetween);
            }

            if (keepCaKey) {
                assertTrue(Files.exists(zipRoot.resolve("ca").resolve("ca.key")));
                // check the CA key
                if (keyPassword != null) {
                    try (Reader reader = Files.newBufferedReader(zipRoot.resolve("ca").resolve("ca.key"))) {
                        PEMParser pemParser = new PEMParser(reader);
                        Object parsed = pemParser.readObject();
                        assertThat(parsed, instanceOf(PEMEncryptedKeyPair.class));
                        char[] zeroChars = new char[caInfo.password.length];
                        Arrays.fill(zeroChars, (char) 0);
                        assertArrayEquals(zeroChars, caInfo.password);
                    }
                }

                PrivateKey privateKey = PemUtils.readPrivateKey(zipRoot.resolve("ca").resolve("ca.key"),
                    () -> keyPassword != null ? keyPassword.toCharArray() : null);
                assertEquals(caInfo.certAndKey.key, privateKey);
            }
        } else {
            assertFalse(Files.exists(zipRoot.resolve("ca")));
        }

        for (CertificateInformation certInfo : certInfos) {
            String filename = certInfo.name.filename;
            assertTrue(Files.exists(zipRoot.resolve(filename)));
            final Path cert = zipRoot.resolve(filename + "/" + filename + ".crt");
            assertTrue(Files.exists(cert));
            assertTrue(Files.exists(zipRoot.resolve(filename + "/" + filename + ".key")));
            final Path p12 = zipRoot.resolve(filename + "/" + filename + ".p12");
            try (InputStream input = Files.newInputStream(cert)) {
                X509Certificate certificate = readX509Certificate(input);
                assertEquals(certInfo.name.x500Principal.toString(), certificate.getSubjectX500Principal().getName());
                final int sanCount = certInfo.ipAddresses.size() + certInfo.dnsNames.size() + certInfo.commonNames.size();
                if (sanCount == 0) {
                    assertNull(certificate.getSubjectAlternativeNames());
                } else {
                    X509CertificateHolder x509CertHolder = new X509CertificateHolder(certificate.getEncoded());
                    GeneralNames subjAltNames =
                            GeneralNames.fromExtensions(x509CertHolder.getExtensions(), Extension.subjectAlternativeName);
                    assertSubjAltNames(subjAltNames, certInfo);
                }
                assertThat(p12, Matchers.not(TestMatchers.pathExists(p12)));
            }
        }
    }

    public void testGetCAInfo() throws Exception {
        Environment env = TestEnvironment.newEnvironment(Settings.builder().put("path.home", createTempDir()).build());
        Path testNodeCertPath = getDataPath("/org/elasticsearch/xpack/security/cli/testnode.crt");
        Path testNodeKeyPath = getDataPath("/org/elasticsearch/xpack/security/cli/testnode.pem");
        final boolean passwordPrompt = randomBoolean();
        MockTerminal terminal = new MockTerminal();
        if (passwordPrompt) {
            terminal.addSecretInput("testnode");
        }

        final int keySize = randomFrom(1024, 2048);
        final int days = randomIntBetween(1, 1024);
        String caPassword = passwordPrompt ? null : "testnode";

        List<String> args = CollectionUtils.arrayAsArrayList(
                "-keysize", String.valueOf(keySize),
                "-days", String.valueOf(days),
                "-pem",
                "-ca-cert", testNodeCertPath.toString(),
                "-ca-key", testNodeKeyPath.toString());

        args.add("-ca-pass");
        if (caPassword != null) {
            args.add(caPassword);
        }

        final GenerateCertificateCommand command = new GenerateCertificateCommand();

        OptionSet options = command.getParser().parse(Strings.toStringArray(args));
        CAInfo caInfo = command.getCAInfo(terminal, options, env);

        assertTrue(terminal.getOutput().isEmpty());
        CertificateTool.CertificateAndKey caCK = caInfo.certAndKey;
        assertEquals(caCK.cert.getSubjectX500Principal().getName(), "CN=Elasticsearch Test Node,OU=elasticsearch,O=org");
        assertThat(caCK.key.getAlgorithm(), containsString("RSA"));
        assertEquals(2048, ((RSAKey) caCK.key).getModulus().bitLength());
        assertFalse(caInfo.generated);
        long daysBetween = getDurationInDays(caCK.cert);
        assertEquals(1460L, daysBetween);

        // test generation
        args = CollectionUtils.arrayAsArrayList(
                "-keysize", String.valueOf(keySize),
                "-days", String.valueOf(days),
                "-pem",
                "-ca-dn", "CN=foo bar");

        final boolean passwordProtected = randomBoolean();
        if (passwordProtected) {
            args.add("-ca-pass");
            if (passwordPrompt) {
                terminal.addSecretInput("testnode");
            } else {
                args.add(caPassword);
            }
        }

        options = command.getParser().parse(Strings.toStringArray(args));
        caInfo = command.getCAInfo(terminal, options, env);
        caCK = caInfo.certAndKey;

        assertTrue(terminal.getOutput().isEmpty());
        assertThat(caCK.cert, instanceOf(X509Certificate.class));
        assertEquals(caCK.cert.getSubjectX500Principal().getName(), "CN=foo bar");
        assertThat(caCK.key.getAlgorithm(), containsString("RSA"));
        assertTrue(caInfo.generated);
        assertEquals(keySize, getKeySize(caCK.key));
        assertEquals(days, getDurationInDays(caCK.cert));
    }

    public void testNameValues() throws Exception {
        // good name
        Name name = Name.fromUserProvidedName("my instance", "my instance");
        assertEquals("my instance", name.originalName);
        assertNull(name.error);
        assertEquals("CN=my instance", name.x500Principal.getName());
        assertEquals("my instance", name.filename);

        // null
        name = Name.fromUserProvidedName(null, "");
        assertEquals("", name.originalName);
        assertThat(name.error, containsString("null"));
        assertNull(name.x500Principal);
        assertNull(name.filename);

        // too long
        String userProvidedName = randomAlphaOfLength(CertificateTool.MAX_FILENAME_LENGTH + 1);
        name = Name.fromUserProvidedName(userProvidedName, userProvidedName);
        assertEquals(userProvidedName, name.originalName);
        assertThat(name.error, containsString("valid filename"));

        // too short
        name = Name.fromUserProvidedName("", "");
        assertEquals("", name.originalName);
        assertThat(name.error, containsString("valid filename"));
        assertEquals("CN=", String.valueOf(name.x500Principal));
        assertNull(name.filename);

        // invalid characters only
        userProvidedName = "<>|<>*|?\"\\";
        name = Name.fromUserProvidedName(userProvidedName, userProvidedName);
        assertEquals(userProvidedName, name.originalName);
        assertThat(name.error, containsString("valid DN"));
        assertNull(name.x500Principal);
        assertNull(name.filename);

        // invalid for file but DN ok
        userProvidedName = "*";
        name = Name.fromUserProvidedName(userProvidedName, userProvidedName);
        assertEquals(userProvidedName, name.originalName);
        assertThat(name.error, containsString("valid filename"));
        assertEquals("CN=" + userProvidedName, name.x500Principal.getName());
        assertNull(name.filename);

        // invalid with valid chars for filename
        userProvidedName = "*.mydomain.com";
        name = Name.fromUserProvidedName(userProvidedName, userProvidedName);
        assertEquals(userProvidedName, name.originalName);
        assertThat(name.error, containsString("valid filename"));
        assertEquals("CN=" + userProvidedName, name.x500Principal.getName());

        // valid but could create hidden file/dir so it is not allowed
        userProvidedName = ".mydomain.com";
        name = Name.fromUserProvidedName(userProvidedName, userProvidedName);
        assertEquals(userProvidedName, name.originalName);
        assertThat(name.error, containsString("valid filename"));
        assertEquals("CN=" + userProvidedName, name.x500Principal.getName());
    }

    /**
     * A multi-stage test that:
     * - Create a new CA
     * - Uses that CA to create 2 node certificates
     * - Creates a 3rd node certificate using an auto-generated CA
     * - Checks that the first 2 node certificates trust one another
     * - Checks that the 3rd node certificate is _not_ trusted
     * - Checks that all 3 certificates have the right values based on the command line options provided during generation
     */
    public void testCreateCaAndMultipleInstances() throws Exception {
        final Path tempDir = initTempDir();

        final Terminal terminal = new MockTerminal();
        Environment env = TestEnvironment.newEnvironment(Settings.builder().put("path.home", tempDir).build());

        final Path caFile = tempDir.resolve("ca.p12");
        final Path node1File = tempDir.resolve("node1.p12").toAbsolutePath();
        final Path node2File = tempDir.resolve("node2.p12").toAbsolutePath();
        final Path node3File = tempDir.resolve("node3.p12").toAbsolutePath();

        final int caKeySize = randomIntBetween(4, 8) * 512;
        final int node1KeySize = randomIntBetween(2, 6) * 512;
        final int node2KeySize = randomIntBetween(2, 6) * 512;
        final int node3KeySize = randomIntBetween(1, 4) * 512;

        final int days = randomIntBetween(7, 1500);

        final String caPassword = randomAlphaOfLengthBetween(4, 16);
        final String node1Password = randomAlphaOfLengthBetween(4, 16);
        final String node2Password = randomAlphaOfLengthBetween(4, 16);
        final String node3Password = randomAlphaOfLengthBetween(4, 16);

        final String node1Ip = "200.181." + randomIntBetween(1, 250) + "." + randomIntBetween(1, 250);
        final String node2Ip = "200.182." + randomIntBetween(1, 250) + "." + randomIntBetween(1, 250);
        final String node3Ip = "200.183." + randomIntBetween(1, 250) + "." + randomIntBetween(1, 250);

        final CertificateAuthorityCommand caCommand = new CertificateAuthorityCommand() {
            @Override
            Path resolveOutputPath(Terminal terminal, OptionSet options, String defaultFilename) throws IOException {
                // Needed to work within the security manager
                return caFile;
            }
        };
        final OptionSet caOptions = caCommand.getParser().parse(
                "-ca-dn", "CN=My ElasticSearch Cluster",
                "-pass", caPassword,
                "-out", caFile.toString(),
                "-keysize", String.valueOf(caKeySize),
                "-days", String.valueOf(days)
        );
        caCommand.execute(terminal, caOptions, env);

        assertThat(caFile, TestMatchers.pathExists(caFile));

        final GenerateCertificateCommand gen1Command = new PathAwareGenerateCertificateCommand(caFile, node1File);
        final OptionSet gen1Options = gen1Command.getParser().parse(
                "-ca", "<ca>",
                "-ca-pass", caPassword,
                "-pass", node1Password,
                "-out", "<node1>",
                "-keysize", String.valueOf(node1KeySize),
                "-days", String.valueOf(days),
                "-dns", "node01.cluster1.es.internal.corp.net",
                "-ip", node1Ip,
                "-name", "node01");
        gen1Command.execute(terminal, gen1Options, env);

        assertThat(node1File, TestMatchers.pathExists(node1File));

        final GenerateCertificateCommand gen2Command = new PathAwareGenerateCertificateCommand(caFile, node2File);
        final OptionSet gen2Options = gen2Command.getParser().parse(
                "-ca", "<ca>",
                "-ca-pass", caPassword,
                "-pass", node2Password,
                "-out", "<node2>",
                "-keysize", String.valueOf(node2KeySize),
                "-days", String.valueOf(days),
                "-dns", "node02.cluster1.es.internal.corp.net",
                "-ip", node2Ip,
                "-name", "node02");
        gen2Command.execute(terminal, gen2Options, env);

        assertThat(node2File, TestMatchers.pathExists(node2File));

        // Node 3 uses an auto generated CA, and therefore should not be trusted by the other nodes.
        final GenerateCertificateCommand gen3Command = new PathAwareGenerateCertificateCommand(null, node3File);
        final OptionSet gen3Options = gen3Command.getParser().parse(
                "-ca-dn", "CN=My ElasticSearch Cluster 2",
                "-pass", node3Password,
                "-out", "<node3>",
                "-keysize", String.valueOf(node3KeySize),
                "-days", String.valueOf(days),
                "-dns", "node03.cluster2.es.internal.corp.net",
                "-ip", node3Ip);
        gen3Command.execute(terminal, gen3Options, env);

        assertThat(node3File, TestMatchers.pathExists(node3File));

        final KeyStore node1KeyStore = CertParsingUtils.readKeyStore(node1File, "PKCS12", node1Password.toCharArray());
        final KeyStore node2KeyStore = CertParsingUtils.readKeyStore(node2File, "PKCS12", node2Password.toCharArray());
        final KeyStore node3KeyStore = CertParsingUtils.readKeyStore(node3File, "PKCS12", node3Password.toCharArray());

        checkTrust(node1KeyStore, node1Password.toCharArray(), node1KeyStore, true);
        checkTrust(node1KeyStore, node1Password.toCharArray(), node2KeyStore, true);
        checkTrust(node2KeyStore, node2Password.toCharArray(), node2KeyStore, true);
        checkTrust(node2KeyStore, node2Password.toCharArray(), node1KeyStore, true);
        checkTrust(node1KeyStore, node1Password.toCharArray(), node3KeyStore, false);
        checkTrust(node3KeyStore, node3Password.toCharArray(), node2KeyStore, false);
        checkTrust(node3KeyStore, node3Password.toCharArray(), node3KeyStore, true);

        final Certificate node1Cert = node1KeyStore.getCertificate("node01");
        assertThat(node1Cert, instanceOf(X509Certificate.class));
        assertSubjAltNames(node1Cert, node1Ip, "node01.cluster1.es.internal.corp.net");
        assertThat(getDurationInDays((X509Certificate) node1Cert), equalTo(days));
        final Key node1Key = node1KeyStore.getKey("node01", node1Password.toCharArray());
        assertThat(getKeySize(node1Key), equalTo(node1KeySize));

        final Certificate node2Cert = node2KeyStore.getCertificate("node02");
        assertThat(node2Cert, instanceOf(X509Certificate.class));
        assertSubjAltNames(node2Cert, node2Ip, "node02.cluster1.es.internal.corp.net");
        assertThat(getDurationInDays((X509Certificate) node2Cert), equalTo(days));
        final Key node2Key = node2KeyStore.getKey("node02", node2Password.toCharArray());
        assertThat(getKeySize(node2Key), equalTo(node2KeySize));

        final Certificate node3Cert = node3KeyStore.getCertificate(CertificateTool.DEFAULT_CERT_NAME);
        assertThat(node3Cert, instanceOf(X509Certificate.class));
        assertSubjAltNames(node3Cert, node3Ip, "node03.cluster2.es.internal.corp.net");
        assertThat(getDurationInDays((X509Certificate) node3Cert), equalTo(days));
        final Key node3Key = node3KeyStore.getKey(CertificateTool.DEFAULT_CERT_NAME, node3Password.toCharArray());
        assertThat(getKeySize(node3Key), equalTo(node3KeySize));
    }


    /**
     * A multi-stage test that:
     * - Creates a ZIP of a PKCS12 cert, with an auto-generated CA
     * - Uses the generate CA to create a PEM certificate
     * - Checks that the PKCS12 certificate and the PEM certificate trust one another
     */
    public void testTrustBetweenPEMandPKCS12() throws Exception {
        final Path tempDir = initTempDir();

        final MockTerminal terminal = new MockTerminal();
        Environment env = TestEnvironment.newEnvironment(Settings.builder().put("path.home", tempDir).build());

        final Path pkcs12Zip = tempDir.resolve("p12.zip");
        final Path pemZip = tempDir.resolve("pem.zip");

        final int keySize = randomIntBetween(4, 8) * 512;
        final int days = randomIntBetween(500, 1500);

        final String caPassword = randomAlphaOfLengthBetween(4, 16);
        final String node1Password = randomAlphaOfLengthBetween(4, 16);

        final GenerateCertificateCommand gen1Command = new PathAwareGenerateCertificateCommand(null, pkcs12Zip);
        final OptionSet gen1Options = gen1Command.getParser().parse(
                "-keep-ca-key",
                "-out", "<zip>",
                "-keysize", String.valueOf(keySize),
                "-days", String.valueOf(days),
                "-dns", "node01.cluster1.es.internal.corp.net",
                "-name", "node01"
        );

        terminal.addSecretInput(caPassword);
        terminal.addSecretInput(node1Password);
        gen1Command.execute(terminal, gen1Options, env);

        assertThat(pkcs12Zip, TestMatchers.pathExists(pkcs12Zip));

        FileSystem zip1FS = FileSystems.newFileSystem(new URI("jar:" + pkcs12Zip.toUri()), Collections.emptyMap());
        Path zip1Root = zip1FS.getPath("/");

        final Path caP12 = zip1Root.resolve("ca/ca.p12");
        assertThat(caP12, TestMatchers.pathExists(caP12));

        final Path node1P12 = zip1Root.resolve("node01/node01.p12");
        assertThat(node1P12, TestMatchers.pathExists(node1P12));

        final GenerateCertificateCommand gen2Command = new PathAwareGenerateCertificateCommand(caP12, pemZip);
        final OptionSet gen2Options = gen2Command.getParser().parse(
                "-ca", "<ca>",
                "-out", "<zip>",
                "-keysize", String.valueOf(keySize),
                "-days", String.valueOf(days),
                "-dns", "node02.cluster1.es.internal.corp.net",
                "-name", "node02",
                "-pem"
        );

        terminal.addSecretInput(caPassword);
        gen2Command.execute(terminal, gen2Options, env);

        assertThat(pemZip, TestMatchers.pathExists(pemZip));

        FileSystem zip2FS = FileSystems.newFileSystem(new URI("jar:" + pemZip.toUri()), Collections.emptyMap());
        Path zip2Root = zip2FS.getPath("/");

        final Path ca2 = zip2Root.resolve("ca/ca.p12");
        assertThat(ca2, Matchers.not(TestMatchers.pathExists(ca2)));

        final Path node2Cert = zip2Root.resolve("node02/node02.crt");
        assertThat(node2Cert, TestMatchers.pathExists(node2Cert));
        final Path node2Key = zip2Root.resolve("node02/node02.key");
        assertThat(node2Key, TestMatchers.pathExists(node2Key));

        final KeyStore node1KeyStore = CertParsingUtils.readKeyStore(node1P12, "PKCS12", node1Password.toCharArray());
        final KeyStore node1TrustStore = node1KeyStore;

        final KeyStore node2KeyStore = CertParsingUtils.getKeyStoreFromPEM(node2Cert, node2Key, new char[0]);
        final KeyStore node2TrustStore = CertParsingUtils.readKeyStore(caP12, "PKCS12", caPassword.toCharArray());

        checkTrust(node1KeyStore, node1Password.toCharArray(), node2TrustStore, true);
        checkTrust(node2KeyStore, new char[0], node1TrustStore, true);
    }

    public void testZipOutputFromCommandLineOptions() throws Exception {
        final Path tempDir = initTempDir();

        final MockTerminal terminal = new MockTerminal();
        Environment env = TestEnvironment.newEnvironment(Settings.builder().put("path.home", tempDir).build());

        final Path zip = tempDir.resolve("pem.zip");

        final AtomicBoolean isZip = new AtomicBoolean(false);
        final GenerateCertificateCommand genCommand = new PathAwareGenerateCertificateCommand(null, zip) {
            @Override
            void generateAndWriteSignedCertificates(Path output, boolean writeZipFile, OptionSet options,
                                                    Collection<CertificateInformation> certs, CAInfo caInfo,
                                                    Terminal terminal) throws Exception {
                isZip.set(writeZipFile);
                // do nothing, all we care about is the "zip" flag
            }

            @Override
            Collection<CertificateInformation> getCertificateInformationList(Terminal terminal, OptionSet options) throws Exception {
                // Regardless of the commandline options, just work with a single cert
                return Collections.singleton(new CertificateInformation("node", "node",
                        Collections.emptyList(), Collections.emptyList(), Collections.emptyList()));
            }
        };

        final String optionThatTriggersZip = randomFrom("-pem", "-keep-ca-key", "-multiple", "-in=input.yml");
        final OptionSet genOptions = genCommand.getParser().parse(
                "-out", "<zip>",
                optionThatTriggersZip
        );
        genCommand.execute(terminal, genOptions, env);

        assertThat("For command line option " + optionThatTriggersZip, isZip.get(), equalTo(true));
    }

    private int getKeySize(Key node1Key) {
        assertThat(node1Key, instanceOf(RSAKey.class));
        return ((RSAKey) node1Key).getModulus().bitLength();
    }

    private int getDurationInDays(X509Certificate cert) {
        return (int) ChronoUnit.DAYS.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant());
    }

    private void assertSubjAltNames(Certificate certificate, String ip, String dns) throws Exception {
        final X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
        final GeneralNames names = GeneralNames.fromExtensions(holder.getExtensions(), Extension.subjectAlternativeName);
        final CertificateInformation certInfo = new CertificateInformation("n", "n", Collections.singletonList(ip),
                Collections.singletonList(dns), Collections.emptyList());
        assertSubjAltNames(names, certInfo);
    }

    /**
     * Checks whether there are keys in {@code keyStore} that are trusted by {@code trustStore}.
     */
    private void checkTrust(KeyStore keyStore, char[] keyPassword, KeyStore trustStore, boolean trust) throws Exception {
        final X509ExtendedKeyManager keyManager = CertParsingUtils.keyManager(keyStore, keyPassword,
            KeyManagerFactory.getDefaultAlgorithm(), null);
        final X509ExtendedTrustManager trustManager = CertParsingUtils.trustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());

        final X509Certificate[] node1CertificateIssuers = trustManager.getAcceptedIssuers();
        final Principal[] trustedPrincipals = new Principal[node1CertificateIssuers.length];
        for (int i = 0; i < node1CertificateIssuers.length; i++) {
            trustedPrincipals[i] = node1CertificateIssuers[i].getIssuerX500Principal();
        }
        final String[] keyAliases = keyManager.getClientAliases("RSA", trustedPrincipals);
        if (trust) {
            assertThat(keyAliases, arrayWithSize(1));
            trustManager.checkClientTrusted(keyManager.getCertificateChain(keyAliases[0]), "RSA");
        } else {
            assertThat(keyAliases, nullValue());
        }
    }

    private PKCS10CertificationRequest readCertificateRequest(Path path) throws Exception {
        try (Reader reader = Files.newBufferedReader(path);
             PEMParser pemParser = new PEMParser(reader)) {
            Object object = pemParser.readObject();
            assertThat(object, instanceOf(PKCS10CertificationRequest.class));
            return (PKCS10CertificationRequest) object;
        }
    }

    private X509Certificate readX509Certificate(InputStream input) throws Exception {
        List<Certificate> list = CertParsingUtils.readCertificates(input);
        assertEquals(1, list.size());
        assertThat(list.get(0), instanceOf(X509Certificate.class));
        return (X509Certificate) list.get(0);
    }

    private void assertSubjAltNames(GeneralNames subjAltNames, CertificateInformation certInfo) throws Exception {
        final int expectedCount = certInfo.ipAddresses.size() + certInfo.dnsNames.size() + certInfo.commonNames.size();
        assertEquals(expectedCount, subjAltNames.getNames().length);
        Collections.sort(certInfo.dnsNames);
        Collections.sort(certInfo.ipAddresses);
        for (GeneralName generalName : subjAltNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dns = ((ASN1String) generalName.getName()).getString();
                assertTrue(certInfo.dnsNames.stream().anyMatch(dns::equals));
            } else if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipBytes = DEROctetString.getInstance(generalName.getName()).getOctets();
                String ip = NetworkAddress.format(InetAddress.getByAddress(ipBytes));
                assertTrue(certInfo.ipAddresses.stream().anyMatch(ip::equals));
            } else if (generalName.getTagNo() == GeneralName.otherName) {
                ASN1Sequence seq = ASN1Sequence.getInstance(generalName.getName());
                assertThat(seq.size(), equalTo(2));
                assertThat(seq.getObjectAt(0), instanceOf(ASN1ObjectIdentifier.class));
                assertThat(seq.getObjectAt(0).toString(), equalTo(CN_OID));
                assertThat(seq.getObjectAt(1), instanceOf(ASN1TaggedObject.class));
                ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(1);
                assertThat(tagged.getObject(), instanceOf(ASN1String.class));
                assertThat(tagged.getObject().toString(), Matchers.isIn(certInfo.commonNames));
            } else {
                fail("unknown general name with tag " + generalName.getTagNo());
            }
        }
    }

    /**
     * Gets a random name that is valid for certificate generation. There are some cases where the random value could match one of the
     * reserved names like ca, so this method allows us to avoid these issues.
     */
    private String getValidRandomInstanceName() {
        String name;
        boolean valid;
        do {
            name = randomAlphaOfLengthBetween(1, 32);
            valid = Name.fromUserProvidedName(name, name).error == null;
        } while (valid == false);
        return name;
    }

    /**
     * Writes the description of instances to a given {@link Path}
     */
    private Path writeInstancesTo(Path path) throws IOException {
        Iterable<String> instances = Arrays.asList(
                "instances:",
                "  - name: \"node1\"",
                "    ip:",
                "      - \"127.0.0.1\"",
                "    dns: \"localhost\"",
                "  - name: \"node2\"",
                "    filename: \"node2\"",
                "    ip: \"::1\"",
                "    cn:",
                "      - \"node2.elasticsearch\"",
                "  - name: \"node3\"",
                "    filename: \"node3\"",
                "  - name: \"CN=different value\"",
                "    filename: \"different file\"",
                "    dns:",
                "      - \"node4.mydomain.com\"");

        return Files.write(path, instances, StandardCharsets.UTF_8);
    }

    /**
     * Writes the description of instances to a given {@link Path}
     */
    private Path writeInvalidInstanceInformation(Path path) throws IOException {
        Iterable<String> instances = Arrays.asList(
                "instances:",
                "  - name: \"THIS=not a,valid DN\"",
                "    ip: \"127.0.0.1\"");
        return Files.write(path, instances, StandardCharsets.UTF_8);
    }

    @SuppressForbidden(reason = "resolve paths against CWD for a CLI tool")
    private static Path resolvePath(String path) {
        return PathUtils.get(path).toAbsolutePath();
    }

    /**
     * Converting jimfs Paths into strings and back to paths doesn't work with the security manager.
     * This class works around that by sticking with the original path objects
     */
    private static class PathAwareGenerateCertificateCommand extends GenerateCertificateCommand {
        private final Path caFile;
        private final Path outFile;

        PathAwareGenerateCertificateCommand(Path caFile, Path outFile) {
            this.caFile = caFile;
            this.outFile = outFile;
        }

        @Override
        protected Path resolvePath(OptionSet options, OptionSpec<String> spec) {
            if (spec.options().contains("ca")) {
                return caFile;
            }
            return super.resolvePath(options, spec);
        }

        @Override
        Path resolveOutputPath(Terminal terminal, OptionSet options, String defaultFilename) throws IOException {
            return outFile;
        }
    }
}
