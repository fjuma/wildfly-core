/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.extension.elytron;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceName;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.cert.KeyUsage;


/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class KeyStoresTestCase extends AbstractSubsystemTest {

    private static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();
    private static CredentialStoreUtility csUtil = null;
    private static final String CS_PASSWORD = "super_secret";
    private static final String KEYSTORE_NAME = "ModifiedKeystore";
    private static final String KEY_PASSWORD = "secret";


    public KeyStoresTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    private ModelNode assertSuccess(ModelNode response) {
        if (!response.get(OUTCOME).asString().equals(SUCCESS)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }

    @BeforeClass
    public static void initTests() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(wildFlyElytronProvider, 1);
            }
        });
        csUtil = new CredentialStoreUtility("target/tlstest.keystore", CS_PASSWORD);
        csUtil.addEntry("the-key-alias", "Elytron");
        csUtil.addEntry("master-password-alias", "Elytron");
    }

    @AfterClass
    public static void cleanUpTests() {
        csUtil.cleanUp();
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(wildFlyElytronProvider.getName());

                return null;
            }
        });
    }

    @Before
    public void init() throws Exception {
        String subsystemXml = System.getProperty("java.vendor").startsWith("IBM") ? "tls-ibm.xml" : "tls-sun.xml";
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource(subsystemXml).build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testKeystoreService() throws Exception {
        ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName("FireflyKeystore");
        KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
        assertNotNull(keyStore);

        assertTrue(keyStore.containsAlias("firefly"));
        assertTrue(keyStore.isKeyEntry("firefly"));
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", cert.getSubjectDN().getName());
        assertEquals("firefly", keyStore.getCertificateAlias(cert));

        Certificate[] chain = keyStore.getCertificateChain("firefly");
        assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", ((X509Certificate) chain[0]).getSubjectDN().getName());
        assertEquals("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA", ((X509Certificate) chain[1]).getSubjectDN().getName());

        assertTrue(keyStore.containsAlias("ca"));
        assertTrue(keyStore.isCertificateEntry("ca"));
        X509Certificate certCa = (X509Certificate) keyStore.getCertificate("ca");
        assertEquals("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA", certCa.getSubjectDN().getName());
        assertEquals("ca", keyStore.getCertificateAlias(certCa));
    }

    @Test
    public void testKeystoreCli() throws Exception {
        Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
        Files.copy(resources.resolve("firefly.keystore"), resources.resolve("firefly-copy.keystore"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        ModelNode operation = new ModelNode(); // add keystore
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", "ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.PATH).set(resources + "/firefly-copy.keystore");
        operation.get(ElytronDescriptionConstants.TYPE).set("JKS");
        operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set("Elytron");
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIASES);
        List<ModelNode> nodes = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
        assertEquals(2, nodes.size());

        operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.REMOVE_ALIAS);
        operation.get(ElytronDescriptionConstants.ALIAS).set("ca");
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIASES);
        nodes = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
        assertEquals(1, nodes.size());

        operation = new ModelNode(); // remove keystore
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));
    }

    @Test
    public void testFilteringKeystoreService() throws Exception {
        ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName("FilteringKeyStore");
        KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
        assertNotNull(keyStore);

        assertTrue(keyStore.containsAlias("firefly"));
        assertTrue(keyStore.isKeyEntry("firefly"));
        assertEquals(2, keyStore.getCertificateChain("firefly").length); // has CA in chain
        Certificate cert = keyStore.getCertificate("firefly");
        assertNotNull(cert);
        assertEquals("firefly", keyStore.getCertificateAlias(cert));

        Assert.assertFalse(keyStore.containsAlias("ca"));
        Assert.assertFalse(keyStore.isCertificateEntry("ca"));
    }

    @Test
    public void testFilteringKeystoreCli() throws Exception {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add(ElytronDescriptionConstants.FILTERING_KEY_STORE,"FilteringKeyStore");
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIASES);
        List<ModelNode> nodes = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
        assertEquals(1, nodes.size());
        assertEquals("firefly", nodes.get(0).asString());

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add(ElytronDescriptionConstants.FILTERING_KEY_STORE,"FilteringKeyStore");
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIAS);
        operation.get(ElytronDescriptionConstants.ALIAS).set("firefly");
        ModelNode firefly = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT);
        assertEquals("firefly", firefly.get(ElytronDescriptionConstants.ALIAS).asString());
        assertEquals(KeyStore.PrivateKeyEntry.class.getSimpleName(), firefly.get(ElytronDescriptionConstants.ENTRY_TYPE).asString());
        assertTrue(firefly.get(ElytronDescriptionConstants.CERTIFICATE_CHAIN).isDefined());
    }

    @Test
    public void testGenerateKeyPair() throws Exception {
        addKeyStore();

        try {
            int numAliasesBefore = readAliases().size();

            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.GENERATE_KEY_PAIR);
            operation.get(ElytronDescriptionConstants.ALIAS).set("bsmith");
            operation.get(ElytronDescriptionConstants.ALGORITHM).set("RSA");
            operation.get(ElytronDescriptionConstants.KEY_SIZE).set(1024);
            operation.get(ElytronDescriptionConstants.VALIDITY).set(365);
            operation.get(ElytronDescriptionConstants.SIGNATURE_ALGORITHM).set("SHA256withRSA");
            operation.get(ElytronDescriptionConstants.DISTINGUISHED_NAME).set("CN=bob smith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us");
            ModelNode extensions = new ModelNode();
            extensions.add(getExtension(false, "ExtendedKeyUsage", "clientAuth"));
            extensions.add(getExtension(true, "KeyUsage", "digitalSignature"));
            extensions.add(getExtension(false, "SubjectAlternativeName", "email:bobsmith@example.com,DNS:bobsmith.example.com"));
            operation.get(ElytronDescriptionConstants.EXTENSIONS).set(extensions);
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set(KEY_PASSWORD);
            assertSuccess(services.executeOperation(operation));
            assertEquals(numAliasesBefore + 1, readAliases().size());

            ModelNode newAlias = readAlias("bsmith");
            assertEquals(KeyStore.PrivateKeyEntry.class.getSimpleName(), newAlias.get(ElytronDescriptionConstants.ENTRY_TYPE).asString());
            assertEquals(1, newAlias.get(ElytronDescriptionConstants.CERTIFICATE_CHAIN).asList().size());

            ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(KEYSTORE_NAME);
            KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
            assertNotNull(keyStore);
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("bsmith");
            assertEquals("RSA", certificate.getPublicKey().getAlgorithm());
            assertEquals(1024, ((RSAKey) certificate.getPublicKey()).getModulus().bitLength());
            Date notBefore = certificate.getNotBefore();
            Date notAfter = certificate.getNotAfter();
            assertEquals(365, (notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24));
            assertEquals("SHA256withRSA", certificate.getSigAlgName());
            assertEquals(new X500Principal("CN=bob smith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us"), certificate.getSubjectX500Principal());
            assertEquals(new X500Principal("CN=bob smith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us"), certificate.getIssuerX500Principal());
            try {
                certificate.verify(certificate.getPublicKey());
            } catch (Exception e) {
                fail("Exception not expected");
            }
            assertEquals(1, certificate.getCriticalExtensionOIDs().size());
            assertEquals(3, certificate.getNonCriticalExtensionOIDs().size());
            assertEquals(Arrays.asList(X500.OID_KP_CLIENT_AUTH), certificate.getExtendedKeyUsage());
            boolean[] keyUsage = certificate.getKeyUsage();
            assertTrue(KeyUsage.digitalSignature.in(keyUsage));
            final Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            assertEquals(2, names.size());
            final Iterator<List<?>> iterator = names.iterator();
            List<?> item = iterator.next();
            assertEquals(2, item.size());
            assertEquals(Integer.valueOf(GeneralName.RFC_822_NAME), item.get(0));
            assertEquals("bobsmith@example.com", item.get(1));
            item = iterator.next();
            assertEquals(2, item.size());
            assertEquals(Integer.valueOf(GeneralName.DNS_NAME), item.get(0));
            assertEquals("bobsmith.example.com", item.get(1));
            assertNotNull(certificate.getExtensionValue(X500.OID_CE_SUBJECT_KEY_IDENTIFIER));

            assertNotNull(keyStore.getKey("bsmith", KEY_PASSWORD.toCharArray()));
        } finally {
            removeKeyStore();
        }
    }

    @Test
    public void testGenerateCertificateSigningRequest() throws Exception {
        String csrFileName = "/generated-csr.csr";
        Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
        File csrFile = new File(resources + csrFileName);
        addKeyStore();

        try {
            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.GENERATE_CERTIFICATE_SIGNING_REQUEST);
            operation.get(ElytronDescriptionConstants.ALIAS).set("ssmith");
            operation.get(ElytronDescriptionConstants.SIGNATURE_ALGORITHM).set("SHA512withRSA");
            operation.get(ElytronDescriptionConstants.DISTINGUISHED_NAME).set("CN=ssmith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us");
            ModelNode extensions = new ModelNode();
            extensions.add(getExtension(false, "ExtendedKeyUsage", "clientAuth"));
            extensions.add(getExtension(true, "KeyUsage", "digitalSignature"));
            operation.get(ElytronDescriptionConstants.EXTENSIONS).set(extensions);
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set(KEY_PASSWORD);
            operation.get(ElytronDescriptionConstants.PATH).set(resources + csrFileName);
            assertSuccess(services.executeOperation(operation));

            assertTrue(csrFile.exists());
            String expectedCsrFileName = "/test-generated-csr.csr";
            File expectedCsrFile = new File(resources + expectedCsrFileName);
            byte[] expectedBytes = Files.readAllBytes(expectedCsrFile.toPath());
            byte[] bytes = Files.readAllBytes(csrFile.toPath());
            assertArrayEquals(expectedBytes, bytes);
        } finally {
            removeKeyStore();
            if (csrFile.exists()) {
                csrFile.delete();
            }
        }
    }

    @Test
    public void testImportSingleCertificateReply() throws Exception {
        String replyFileName = "/test-single-cert-reply.cert";
        testImportCertificate(replyFileName);
    }

    @Test
    public void testImportCertificateChainReply() throws Exception {
        String replyFileName = "/test-cert-chain-reply.cert";
        testImportCertificate(replyFileName);
    }

    private void testImportCertificate(String replyFileName) throws Exception {
        addKeyStore();

        try {
            ModelNode alias = readAlias("ssmith");
            assertEquals(KeyStore.PrivateKeyEntry.class.getSimpleName(), alias.get(ElytronDescriptionConstants.ENTRY_TYPE).asString());
            assertEquals(1, alias.get(ElytronDescriptionConstants.CERTIFICATE_CHAIN).asList().size());

            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.IMPORT_CERTIFICATE);
            operation.get(ElytronDescriptionConstants.ALIAS).set("ssmith");
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set(KEY_PASSWORD);
            Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
            operation.get(ElytronDescriptionConstants.PATH).set(resources + replyFileName);
            assertSuccess(services.executeOperation(operation));

            alias = readAlias("ssmith");
            assertEquals(KeyStore.PrivateKeyEntry.class.getSimpleName(), alias.get(ElytronDescriptionConstants.ENTRY_TYPE).asString());
            assertEquals(2, alias.get(ElytronDescriptionConstants.CERTIFICATE_CHAIN).asList().size());

            ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(KEYSTORE_NAME);
            KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
            assertNotNull(keyStore);
            Certificate[] chain = keyStore.getCertificateChain("ssmith");
            X509Certificate firstCertificate = (X509Certificate) chain[0];
            X509Certificate secondCertificate = (X509Certificate) chain[1];
            assertEquals(new X500Principal("CN=ssmith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us"), firstCertificate.getSubjectX500Principal());
            assertEquals(new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA"), firstCertificate.getIssuerX500Principal());
            assertEquals(new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA"), secondCertificate.getSubjectX500Principal());
            assertEquals(new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA"), secondCertificate.getIssuerX500Principal());
        } finally {
            removeKeyStore();
        }
    }

    @Test
    public void testImportTrustedCertificate() throws Exception {
        String replyFileName = "/test-trusted.cert";
        addKeyStore();

        try {
            int numAliasesBefore = readAliases().size();

            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.IMPORT_CERTIFICATE);
            operation.get(ElytronDescriptionConstants.ALIAS).set("anotherCA");
            Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
            operation.get(ElytronDescriptionConstants.PATH).set(resources + replyFileName);
            operation.get(ElytronDescriptionConstants.VALIDATE).set(false);
            assertSuccess(services.executeOperation(operation));
            assertEquals(numAliasesBefore + 1, readAliases().size());

            ModelNode alias = readAlias("anotherCA");
            assertEquals(KeyStore.TrustedCertificateEntry.class.getSimpleName(), alias.get(ElytronDescriptionConstants.ENTRY_TYPE).asString());
            assertTrue(alias.get(ElytronDescriptionConstants.CERTIFICATE).isDefined());

            ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(KEYSTORE_NAME);
            KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
            assertNotNull(keyStore);
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("anotherCA");
            assertEquals(new X500Principal("O=Another Root Certificate Authority, EMAILADDRESS=anotherca@wildfly.org, C=UK, ST=Elytron, CN=Another Elytron CA"), certificate.getSubjectX500Principal());
            assertEquals(new X500Principal("O=Another Root Certificate Authority, EMAILADDRESS=anotherca@wildfly.org, C=UK, ST=Elytron, CN=Another Elytron CA"), certificate.getIssuerX500Principal());
        } finally {
            removeKeyStore();
        }
    }

    @Test
    public void testExportCertificate() throws Exception {
        String expectedCertificateFileName = "/test-exported.cert";
        testExportCertificate(expectedCertificateFileName, false);
    }

    @Test
    public void testExportCertificatePem() throws Exception {
        String expectedCertificateFileName = "/test-exported-pem.cert";
        testExportCertificate(expectedCertificateFileName, true);
    }

    private void testExportCertificate(String expectedCertificateFileName, boolean pem) throws Exception {
        String certificateFileName = "/exported-cert.cert";
        Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
        File certificateFile = new File(resources + certificateFileName);
        addKeyStore();

        try {
            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.EXPORT_CERTIFICATE);
            operation.get(ElytronDescriptionConstants.ALIAS).set("ssmith");
            operation.get(ElytronDescriptionConstants.PATH).set(resources + certificateFileName);
            if (pem) {
                operation.get(ElytronDescriptionConstants.PEM).set(true);
            }
            assertSuccess(services.executeOperation(operation));

            assertTrue(certificateFile.exists());
            File expectedCertificateFile = new File(resources + expectedCertificateFileName);
            byte[] expectedBytes = Files.readAllBytes(expectedCertificateFile.toPath());
            byte[] bytes = Files.readAllBytes(certificateFile.toPath());
            assertArrayEquals(expectedBytes, bytes);
        } finally {
            removeKeyStore();
            if (certificateFile.exists()) {
                certificateFile.delete();
            }
        }
    }

    @Test
    public void testChangeAlias() throws Exception {
        addKeyStore();

        try {
            int numAliasesBefore = readAliases().size();

            ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(KEYSTORE_NAME);
            KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
            assertNotNull(keyStore);
            KeyStore.PrivateKeyEntry aliasBefore = (KeyStore.PrivateKeyEntry) keyStore.getEntry("ssmith", new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray()));

            ModelNode operation = new ModelNode();
            operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", KEYSTORE_NAME);
            operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.CHANGE_ALIAS);
            operation.get(ElytronDescriptionConstants.ALIAS).set("ssmith");
            operation.get(ElytronDescriptionConstants.NEW_ALIAS).set("sallysmith");
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set(KEY_PASSWORD);
            assertSuccess(services.executeOperation(operation));
            assertEquals(numAliasesBefore, readAliases().size());

            keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
            assertNotNull(keyStore);
            assertTrue(!keyStore.containsAlias("ssmith"));
            KeyStore.PrivateKeyEntry aliasAfter = (KeyStore.PrivateKeyEntry) keyStore.getEntry("sallysmith", new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray()));
            assertEquals(aliasBefore.getCertificate(), aliasAfter.getCertificate());
            assertArrayEquals(aliasBefore.getCertificateChain(), aliasAfter.getCertificateChain());
            assertEquals(aliasBefore.getPrivateKey(), aliasAfter.getPrivateKey());
        } finally {
            removeKeyStore();
        }
    }

    private void addKeyStore() throws Exception {
        Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
        Files.copy(resources.resolve("test.keystore"), resources.resolve("test-copy.keystore"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", KEYSTORE_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.PATH).set(resources + "/test-copy.keystore");
        operation.get(ElytronDescriptionConstants.TYPE).set("JKS");
        operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set("Elytron");
        assertSuccess(services.executeOperation(operation));
    }

    private List<ModelNode> readAliases() {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", KEYSTORE_NAME);
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIASES);
        return assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
    }

    private ModelNode readAlias(String aliasName) {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", KEYSTORE_NAME);
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.READ_ALIAS);
        operation.get(ElytronDescriptionConstants.ALIAS).set(aliasName);
        ModelNode alias = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT);
        assertEquals(aliasName, alias.get(ElytronDescriptionConstants.ALIAS).asString());
        return alias;
    }

    private ModelNode getExtension(boolean critical, String name, String value) {
        ModelNode extension = new ModelNode();
        extension.get(ElytronDescriptionConstants.CRITICAL).set(critical);
        extension.get(ElytronDescriptionConstants.NAME).set(name);
        extension.get(ElytronDescriptionConstants.VALUE).set(value);
        return extension;
    }

    private void removeKeyStore() {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", KEYSTORE_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));
    }
}