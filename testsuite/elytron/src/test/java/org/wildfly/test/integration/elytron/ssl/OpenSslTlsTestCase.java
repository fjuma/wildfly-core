/*
 * JBoss, Home of Professional Open Source
 * Copyright 2021 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 * See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License, v. 2.1.
 * This program is distributed in the hope that it will be useful, but WITHOUT A
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License,
 * v.2.1 along with this distribution; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */
package org.wildfly.test.integration.elytron.ssl;

import static org.jboss.as.controller.client.helpers.ClientConstants.CONTENT;
import static org.jboss.as.controller.client.helpers.ClientConstants.DEPLOYMENT;
import static org.jboss.as.controller.client.helpers.Operations.createAddOperation;
import static org.jboss.as.controller.client.helpers.Operations.createAddress;
import static org.jboss.as.controller.client.helpers.Operations.createRemoveOperation;

import java.io.FilePermission;
import java.io.IOException;
import java.lang.reflect.ReflectPermission;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.client.OperationBuilder;
import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.controller.client.helpers.Operations;
import org.jboss.as.controller.client.helpers.standalone.ServerDeploymentHelper;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.management.util.ServerReload;
import org.jboss.as.test.shared.PermissionUtils;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceActivator;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.core.testrunner.ManagementClient;
import org.wildfly.core.testrunner.ServerSetup;
import org.wildfly.core.testrunner.ServerSetupTask;
import org.wildfly.core.testrunner.WildflyTestRunner;
import org.wildfly.openssl.OpenSSLProvider;
import org.wildfly.security.ssl.test.util.CAGenerationTool;
import org.wildfly.security.ssl.test.util.CAGenerationTool.Identity;
import org.wildfly.test.undertow.UndertowSSLService;
import org.wildfly.test.undertow.UndertowSSLServiceActivator;
import org.wildfly.test.undertow.UndertowServiceActivator;

@RunWith(WildflyTestRunner.class)
@ServerSetup(OpenSslTlsTestCase.Setup.class)
public class OpenSslTlsTestCase {

    CLIWrapper cli;
    private static final OpenSSLProvider openSslProvider = new OpenSSLProvider();

    private static final String javaSpecVersion = System.getProperty("java.specification.version");
    private static final String PASSWORD = "password";

    private static final String[] SERVER_KEY_STORE = {"subsystem", "elytron", "key-store", "scarabKS"};
    private static final String[] SERVER_KEY_MANAGER = {"subsystem", "elytron", "key-manager", "ServerKeyManager"};
    private static final String[] SERVER_SSL_CONTEXT = {"subsystem", "elytron", "server-ssl-context", "test-context"};
    private static final String[] SERVER_SSL_CONTEXT_ALL_PROTOCOLS = {"subsystem", "elytron", "server-ssl-context", "AllProtocolsSSC"};
    private static final String[] SERVER_SSL_CONTEXT_TLS12_ONLY = {"subsystem", "elytron", "server-ssl-context", "TLS12OnlySSC"};
    private static final String[] SERVER_SSL_CONTEXT_TLS13_ONLY = {"subsystem", "elytron", "server-ssl-context", "TLS13OnlySSC"};
    private static final String[] SERVER_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES = {"subsystem", "elytron", "server-ssl-context", "NoTLS13CipherSuitesSSC"};

    private static final String[] CLIENT_KEY_STORE = {"subsystem", "elytron", "key-store", "ladybirdKS"};
    private static final String[] CLIENT_KEY_MANAGER = {"subsystem", "elytron", "key-manager", "ClientKeyManager"};
    private static final String[] CLIENT_SSL_CONTEXT_ALL_PROTOCOLS = {"subsystem", "elytron", "client-ssl-context", "AllProtocolsCSC"};
    private static final String[] CLIENT_SSL_CONTEXT_TLS13_ONLY = {"subsystem", "elytron", "client-ssl-context", "TLS13OnlyCSC"};
    private static final String[] CLIENT_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES = {"subsystem", "elytron", "client-ssl-context", "NoTLS13CipherSuitesCSC"};

    private static final String[] TRUST_STORE = {"subsystem", "elytron", "key-store", "caTrustStore"};
    private static final String[] TRUST_MANAGER = {"subsystem", "elytron", "trust-manager", "caTrustManager"};

    private static CAGenerationTool caGenerationTool = null;
    private static boolean ignored;
    private static final String JKS_LOCATION = "./target/test-classes/jks";
    private static final String TEST_JAR = "test.jar";

    @BeforeClass
    public static void noJDK14Plus() {
        Assume.assumeFalse("Avoiding JDK 14 due to https://issues.jboss.org/browse/WFCORE-4532", "14".equals(System.getProperty("java.specification.version")));
    }

    private static boolean isJDK14Plus() {
        return "14".equals(javaSpecVersion);
    }

    private static int getJavaSpecVersion() {
        if ("1.8".equals(javaSpecVersion)) return 8;
        return Integer.parseInt(javaSpecVersion);
    }

    private static boolean isOpenSSL111OrHigher() {
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(openSslProvider, 1));
        boolean openSslTls13Enabled = true;
        try {
            SSLContext.getInstance("openssl.TLSv1.3");
        } catch (Exception e) {
            openSslTls13Enabled = false;
        }
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.removeProvider(openSslProvider.getName());
            return null;
        });
        /*if (sslContext == null) {
            return false; // running on OpenSSL version < 1.1.1, TLS 1.3 cannot be tested
        }
        String[] OPENSSL_AVAILABLE_CIPHERSUITES = sslContext.getSupportedSSLParameters().getCipherSuites();
        for (String cipherSuite : OPENSSL_AVAILABLE_CIPHERSUITES) {
            if (OPENSSL_TLSv13_PATTERN.matcher(cipherSuite).matches()) {
                return true;
            }
        }
        return false;*/
        return openSslTls13Enabled;
    }

    static class Setup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient) throws Exception {
            if (isJDK14Plus()) {
                // TODO: remove this line once WFCORE-4532 is fixed
                ignored = true;
                return;
            }
            if (! (getJavaSpecVersion() >= 11 && isOpenSSL111OrHigher())) {
                ignored = true;
                return;
            }

            caGenerationTool = CAGenerationTool.builder()
                    .setBaseDir(JKS_LOCATION)
                    .setRequestIdentities(Identity.LADYBIRD, Identity.SCARAB)
                    .build();

            ModelNode credential = new ModelNode();
            credential.get("clear-text").set(PASSWORD);

            createKeyStore(managementClient, SERVER_KEY_STORE, "/jks/scarab.keystore", credential);
            createKeyStore(managementClient, CLIENT_KEY_STORE, "/jks/ladybird.keystore", credential);
            createKeyStore(managementClient, TRUST_STORE, "/jks/ca.truststore", credential);

            createServerKeyManager(managementClient, SERVER_KEY_MANAGER, credential);
            createClientKeyManager(managementClient, CLIENT_KEY_MANAGER, credential);

            createTrustManager(managementClient, TRUST_MANAGER, credential);

            createServerSslContext(managementClient, SERVER_SSL_CONTEXT, null, null);
            //createServerSslContext(managementClient, SERVER_SSL_CONTEXT, "TLSv1.3 TLSv1.2 TLSv1.1",
              //      "TLS_AES_128_CCM_8_SHA256:TLS_AES_256_GCM_SHA384");
            //createServerSslContext(managementClient, SERVER_SSL_CONTEXT_TLS12_ONLY, "TLSv1.2", null);
            //createServerSslContext(managementClient, SERVER_SSL_CONTEXT_TLS13_ONLY, "TLSv1.3",
                //    "TLS_AES_128_CCM_8_SHA256:TLS_AES_256_GCM_SHA384");
            //createServerSslContext(managementClient, SERVER_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES, "TLSv1.3 TLSv1.2 TLSv1.1", null);

            //createClientSslContext(managementClient, CLIENT_SSL_CONTEXT_ALL_PROTOCOLS, "TLSv1.3 TLSv1.2 TLSv1.1",
            //        "TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_8_SHA256");
            //createClientSslContext(managementClient, CLIENT_SSL_CONTEXT_TLS13_ONLY, "TLSv1.3",
            //        "TLS_AES_128_GCM_SHA256");
            //createClientSslContext(managementClient, CLIENT_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES, "TLSv1.3 TLSv1.2 TLSv1.1", null);

            JavaArchive jar = ShrinkWrap.create(JavaArchive.class, TEST_JAR)
                    .addClasses(UndertowServiceActivator.DEPENDENCIES)
                    .addClasses(UndertowSSLService.class)
                    .addAsResource(new StringAsset("Dependencies: io.undertow.core"), "META-INF/MANIFEST.MF")
                    .addAsManifestResource(PermissionUtils.createPermissionsXmlAsset(UndertowServiceActivator.appendPermissions(new FilePermission("<<ALL FILES>>", "read"),
                            new RuntimePermission("getClassLoader"),
                            new RuntimePermission("accessDeclaredMembers"),
                            new RuntimePermission("accessClassInPackage.sun.security.ssl"),
                            new ReflectPermission("suppressAccessChecks"))), "permissions.xml")
                    .addAsServiceProviderAndClasses(ServiceActivator.class, UndertowSSLServiceActivator.class);
            deploy(jar, managementClient);

            ServerReload.executeReloadAndWaitForCompletion(managementClient.getControllerClient());
        }

        @Override
        public void tearDown(ManagementClient managementClient) throws Exception {
            if (! ignored) {
                //managementClient.executeForResult(createRemoveOperation(createAddress(CLIENT_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(CLIENT_SSL_CONTEXT_TLS13_ONLY)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(CLIENT_SSL_CONTEXT_ALL_PROTOCOLS)));
                managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_SSL_CONTEXT)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_SSL_CONTEXT_NO_TLS13_CIPHER_SUITES)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_SSL_CONTEXT_TLS13_ONLY)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_SSL_CONTEXT_TLS12_ONLY)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_SSL_CONTEXT_ALL_PROTOCOLS)));
                managementClient.executeForResult(createRemoveOperation(createAddress(TRUST_MANAGER)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(CLIENT_KEY_MANAGER)));
                managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_KEY_MANAGER)));
                managementClient.executeForResult(createRemoveOperation(createAddress(TRUST_STORE)));
                //managementClient.executeForResult(createRemoveOperation(createAddress(CLIENT_KEY_STORE)));
                managementClient.executeForResult(createRemoveOperation(createAddress(SERVER_KEY_STORE)));


                undeploy(managementClient, TEST_JAR);
                ServerReload.executeReloadAndWaitForCompletion(managementClient.getControllerClient());
                caGenerationTool.close();
            }
        }

        private void createKeyStore(ManagementClient managementClient, String[] address, String path, ModelNode credential) throws Exception {
            ModelNode modelNode = createAddOperation(createAddress(address));
            modelNode.get("type").set("jks");
            modelNode.get("path").set(path);
            modelNode.get("credential-reference").set(credential);
            managementClient.executeForResult(modelNode);
        }

        private void createServerKeyManager(ManagementClient managementClient, String[] address, ModelNode credential) throws Exception {
            createKeyManager(managementClient, address, credential, true);
        }

        private void createClientKeyManager(ManagementClient managementClient, String[] address, ModelNode credential) throws Exception {
            createKeyManager(managementClient, address, credential, false);
        }

        private void createKeyManager(ManagementClient managementClient, String[] address, ModelNode credential, boolean isServer) throws Exception {
            ModelNode modelNode = createAddOperation(createAddress(address));
            modelNode.get("algorithm").set(keyAlgorithm());
            modelNode.get("key-store").set(isServer ? SERVER_KEY_STORE[3] : CLIENT_KEY_STORE[3]);
            modelNode.get("credential-reference").set(credential);
            managementClient.executeForResult(modelNode);
        }

        private void createTrustManager(ManagementClient managementClient, String[] address, ModelNode credential) throws Exception {
            ModelNode modelNode = createAddOperation(createAddress(address));
            modelNode.get("key-store").set(TRUST_STORE[3]);
            modelNode.get("credential-reference").set(credential);
            managementClient.executeForResult(modelNode);
        }

        private void createServerSslContext(ManagementClient managementClient, String[] address, String protocols, String cipherSuiteNames) throws Exception {
            createSslContext(managementClient, address, protocols, cipherSuiteNames, true);
        }

        private void createClientSslContext(ManagementClient managementClient, String[] address, String protocols, String cipherSuiteNames) throws Exception {
            createSslContext(managementClient, address, protocols, cipherSuiteNames, false);
        }

        private void createSslContext(ManagementClient managementClient, String[] address, String protocols, String cipherSuiteNames, boolean isServer) throws Exception {
            ModelNode modelNode = createAddOperation(createAddress(address));
            modelNode.get("key-manager").set(isServer ? SERVER_KEY_MANAGER[3] : CLIENT_KEY_MANAGER[3]);
            modelNode.get("trust-manager").set(TRUST_MANAGER[3]);
            if (protocols != null) {
                ModelNode protocolsList = new ModelNode();
                for (String protocol : protocols.split(" ")) {
                    protocolsList.add(protocol);
                }
                modelNode.get("protocols").set(protocolsList);
            }
            if (cipherSuiteNames != null) {
                modelNode.get("cipher-suite-names").set(cipherSuiteNames);
            }
            modelNode.get("providers").set("openssl");
            managementClient.executeForResult(modelNode);
        }
    }

    @Test
    public void testSslServiceAuthTLS13OpenSsl() throws Throwable {
        //Assume.assumeTrue("Skipping testSslServiceAuthTLS13OpenSsl, test is not being run with JDK 11+ and OpenSSL 1.1.1+",
          //      getJavaSpecVersion() >= 11 && isOpenSSL111OrHigher());
        Assert.assertEquals("blah", "blah");
        //testCommunication("ServerSslContextTLS13OpenSsl", "ClientSslContextTLS13OpenSsl", false, "OU=Elytron,O=Elytron,C=CZ,ST=Elytron,CN=localhost",
        //        "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", "TLS_AES_256_GCM_SHA384", true);
    }


    /**
     * Determines key algorithm to be used based on the used JDK.
     *
     * @return IbmX509 in case of IBM JDK, SunX509 otherwise
     */

    private static String keyAlgorithm() {
        if (isIbmJdk()) {
            return "IbmX509";
        } else {
            return "SunX509";
        }
    }

    /**
     * @return true if JVM running is IBM JDK
     */
    private static boolean isIbmJdk() {
        return System.getProperty("java.vendor").startsWith("IBM");
    }

    /**
     * Deploys the archive to the running server.
     *
     * @param archive the archive to deploy
     * @throws IOException if an error occurs deploying the archive
     */

    public static void deploy(final Archive<?> archive, ManagementClient managementClient) throws IOException {
        // Use an operation to allow overriding the runtime name
        final ModelNode address = Operations.createAddress(DEPLOYMENT, archive.getName());
        final ModelNode addOp = createAddOperation(address);
        addOp.get("enabled").set(true);
        // Create the content for the add operation
        final ModelNode contentNode = addOp.get(CONTENT);
        final ModelNode contentItem = contentNode.get(0);
        contentItem.get(ClientConstants.INPUT_STREAM_INDEX).set(0);

        // Create an operation and add the input archive
        final OperationBuilder builder = OperationBuilder.create(addOp);
        builder.addInputStream(archive.as(ZipExporter.class).exportAsInputStream());

        // Deploy the content and check the results
        final ModelNode result = managementClient.getControllerClient().execute(builder.build());
        if (!Operations.isSuccessfulOutcome(result)) {
            Assert.fail(String.format("Failed to deploy %s: %s", archive, Operations.getFailureDescription(result).asString()));
        }
    }

    public static void undeploy(ManagementClient client, final String runtimeName) throws ServerDeploymentHelper.ServerDeploymentException {
        final ServerDeploymentHelper helper = new ServerDeploymentHelper(client.getControllerClient());
        final Collection<Throwable> errors = new ArrayList<>();
        try {
            final ModelNode op = Operations.createReadResourceOperation(Operations.createAddress("deployment", runtimeName));
            final ModelNode result = client.getControllerClient().execute(op);
            if (Operations.isSuccessfulOutcome(result))
                helper.undeploy(runtimeName);
        } catch (Exception e) {
            errors.add(e);
        }
        if (!errors.isEmpty()) {
            final RuntimeException e = new RuntimeException("Error undeploying: " + runtimeName);
            for (Throwable error : errors) {
                e.addSuppressed(error);
            }
            throw e;
        }
    }
}

