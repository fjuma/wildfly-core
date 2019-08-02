/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2019 Red Hat, Inc. and/or its affiliates.
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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.NAME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.jboss.as.controller.security.CredentialReference.ALIAS;
import static org.jboss.as.controller.security.CredentialReference.CLEAR_TEXT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceName;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class CredentialStoreUpdatesTestCase extends AbstractSubsystemTest {

    private static final String CS_PASSWORD = "super_secret";
    private static final String EMPTY_CS_NAME1 = "store1";
    private static final String EMPTY_CS_PATH1 = "target/test.credential.store1";
    private static final String EMPTY_CS_NAME2 = "store2";
    private static final String EMPTY_CS_PATH2 = "target/test.credential.store2";
    private static final String NON_EMPTY_CS_NAME = "store3";
    private static final String NON_EMPTY_CS_PATH = "target/test.credential.store3";
    private static final String KS_NAME = "test-keystore";
    private static final String CLEAR_TEXT_ATTRIBUTE_NAME = CredentialReference.CREDENTIAL_REFERENCE + "." + CLEAR_TEXT;
    private static final String ALIAS_ATTRIBUTE_NAME = CredentialReference.CREDENTIAL_REFERENCE + "." + ALIAS;
    private static final String EXISTING_ALIAS = "existingAlias";
    private static final String EXISTING_PASSWORD = "existingPassword";
    private static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();
    private static CredentialStoreUtility emptyCSUtil1 = null;
    private static CredentialStoreUtility emptyCSUtil2 = null;
    private static CredentialStoreUtility nonEmptyCSUtil = null;
    private KernelServices services = null;

    public CredentialStoreUpdatesTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    @BeforeClass
    public static void initTests() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(wildFlyElytronProvider, 1);
            }
        });
    }

    @Before
    public void init() throws Exception {
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("credential-store-updates.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
        nonEmptyCSUtil = new CredentialStoreUtility(NON_EMPTY_CS_PATH, CS_PASSWORD);
        emptyCSUtil1 = new CredentialStoreUtility(EMPTY_CS_PATH1, CS_PASSWORD);
        emptyCSUtil2 = new CredentialStoreUtility(EMPTY_CS_PATH2, CS_PASSWORD);
    }

    @After
    public void cleanUpCredentialStores() {
        nonEmptyCSUtil.cleanUp();
        emptyCSUtil1.cleanUp();
        emptyCSUtil2.cleanUp();
    }

    @AfterClass
    public static void cleanUpTests() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(wildFlyElytronProvider.getName());
                return null;
            }
        });
    }

    @Test
    public void testCredentialReferenceAddNewEntryToEmptyCredentialStore() throws Exception {
        String alias = "newAlias";
        String password = "newPassword";
        try {
            CredentialStore credentialStore = getCredentialStore(EMPTY_CS_NAME1);
            assertEquals(0, credentialStore.getAliases().size());

            addKeyStoreWithCredentialStoreUpdate(KS_NAME, EMPTY_CS_NAME1, alias, password, false);
            assertEquals(1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(alias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(alias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(alias, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceAddNewEntryWithGeneratedAliasToEmptyCredentialStore() throws Exception {
        String password = "newPassword";
        try {
            CredentialStore credentialStore = getCredentialStore(EMPTY_CS_NAME2);
            assertEquals(0, credentialStore.getAliases().size());

            String generatedAlias = addKeyStoreWithCredentialStoreUpdate(KS_NAME, EMPTY_CS_NAME2,null, password, false);
            assertEquals(1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(generatedAlias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(generatedAlias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(generatedAlias, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceAddNewEntry() throws Exception {
        String alias = "newAlias";
        String password = "newPassword";
        try {
            CredentialStore credentialStore = getCredentialStore();
            assertFalse(credentialStore.exists(alias, PasswordCredential.class));
            int numAliases = credentialStore.getAliases().size();

            addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, alias, password, false);
            assertEquals(numAliases + 1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(alias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(alias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(alias, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceAddNewEntryWithGeneratedAlias() throws Exception {
        String password = "newPassword";
        try {
            CredentialStore credentialStore = getCredentialStore();
            int numAliases = credentialStore.getAliases().size();

            String generatedAlias = addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME,  null, password, false);
            assertEquals(numAliases + 1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(generatedAlias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(generatedAlias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(generatedAlias, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceUpdateExistingEntry() throws Exception {
        String newPassword = "newPassword";
        try {
            CredentialStore credentialStore = getCredentialStore();
            credentialStore.store(EXISTING_ALIAS, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, EXISTING_PASSWORD.toCharArray())));
            credentialStore.flush();

            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(EXISTING_PASSWORD.toCharArray(), clearPassword.getPassword()));
            int numAliases = credentialStore.getAliases().size();

            addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, EXISTING_ALIAS, newPassword, true);
            assertEquals(numAliases, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(newPassword.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(EXISTING_ALIAS, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceAddNewEntryFromOperation() throws Exception {
        try {
            CredentialStore credentialStore = getCredentialStore();
            credentialStore.store(EXISTING_ALIAS, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, EXISTING_PASSWORD.toCharArray())));
            credentialStore.flush();
            addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, EXISTING_ALIAS, null, true, false);

            String alias = "newAlias";
            String password = "newPassword";
            assertFalse(credentialStore.exists(alias, PasswordCredential.class));
            int numAliases = credentialStore.getAliases().size();

            // specify a credential-reference when executing a key-store operation
            generateKeyPairWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, alias, password, false);
            assertEquals(numAliases + 1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(alias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(alias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceAddNewEntryWithGeneratedAliasFromOperation() throws Exception {
        try {
            CredentialStore credentialStore = getCredentialStore();
            credentialStore.store(EXISTING_ALIAS, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, EXISTING_PASSWORD.toCharArray())));
            credentialStore.flush();
            addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, EXISTING_ALIAS, null, true, false);

            String password = "newPassword";
            int numAliases = credentialStore.getAliases().size();

            // specify a credential-reference when executing a key-store operation
            String generatedAlias = generateKeyPairWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, null, password, false);
            assertEquals(numAliases + 1, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(generatedAlias, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(generatedAlias, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceUpdateExistingEntryFromOperation() throws Exception {
        try {
            addKeyStoreWithCredentialStoreUpdate(KS_NAME, EMPTY_CS_NAME1, "alias1", "secret", false, false);

            CredentialStore credentialStore = getCredentialStore();
            credentialStore.store(EXISTING_ALIAS, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, EXISTING_PASSWORD.toCharArray())));
            credentialStore.flush();
            int numAliases = credentialStore.getAliases().size();
            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(EXISTING_PASSWORD.toCharArray(), clearPassword.getPassword()));

            // specify a credential-reference when executing a key-store operation
            String password = "newPassword";
            generateKeyPairWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, EXISTING_ALIAS, password, true);

            assertEquals(numAliases, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(password.toCharArray(), clearPassword.getPassword()));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    @Test
    public void testCredentialReferenceNoUpdate() throws Exception {
        try {
            CredentialStore credentialStore = getCredentialStore();
            credentialStore.store(EXISTING_ALIAS, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, EXISTING_PASSWORD.toCharArray())));
            credentialStore.flush();

            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            PasswordCredential passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(EXISTING_PASSWORD.toCharArray(), clearPassword.getPassword()));
            int numAliases = credentialStore.getAliases().size();

            addKeyStoreWithCredentialStoreUpdate(KS_NAME, NON_EMPTY_CS_NAME, EXISTING_ALIAS, null, true);
            assertEquals(numAliases, credentialStore.getAliases().size());
            assertTrue(credentialStore.exists(EXISTING_ALIAS, PasswordCredential.class));
            passwordCredential = credentialStore.retrieve(EXISTING_ALIAS, PasswordCredential.class);
            clearPassword = passwordCredential.getPassword(ClearPassword.class);
            assertTrue(Arrays.equals(EXISTING_PASSWORD.toCharArray(), clearPassword.getPassword()));

            assertEquals(null, readAttribute(KS_NAME, CLEAR_TEXT_ATTRIBUTE_NAME));
            assertEquals(EXISTING_ALIAS, readAttribute(KS_NAME, ALIAS_ATTRIBUTE_NAME));
        } finally {
            removeKeyStore(KS_NAME);
        }
    }

    private String addKeyStoreWithCredentialStoreUpdate(String keyStoreName, String store, String alias, String secret, boolean exists) throws Exception {
        return addKeyStoreWithCredentialStoreUpdate(keyStoreName, store, alias, secret, exists, true);
    }

    private String addKeyStoreWithCredentialStoreUpdate(String keyStoreName, String store, String alias, String secret, boolean exists, boolean validateResponse) throws Exception {
        Path resources = Paths.get(KeyStoresTestCase.class.getResource(".").toURI());
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", keyStoreName);
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.PATH).set(resources + "/test.keystore");
        operation.get(ElytronDescriptionConstants.TYPE).set("JKS");
        operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.STORE).set(store);
        boolean autoGeneratedAlias = false;
        if (alias != null) {
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(ALIAS).set(alias);
        } else {
            autoGeneratedAlias = true;
        }
        if (secret != null) {
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CLEAR_TEXT).set(secret);
        }
        ModelNode response = assertSuccess(services.executeOperation(operation)).get(RESULT);
        if (validateResponse) {
            return validateResponse(response, secret, autoGeneratedAlias, exists);
        } else {
            return null;
        }
    }

    private String generateKeyPairWithCredentialStoreUpdate(String keyStoreName, String store, String alias, String secret, boolean exists) {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("key-store", keyStoreName);
        operation.get(ClientConstants.OP).set(ElytronDescriptionConstants.GENERATE_KEY_PAIR);
        operation.get(ElytronDescriptionConstants.ALIAS).set("bsmith");
        operation.get(ElytronDescriptionConstants.DISTINGUISHED_NAME).set("CN=bob smith");
        operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.STORE).set(store);
        boolean autoGeneratedAlias = false;
        if (alias != null) {
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.ALIAS).set(alias);
        } else {
            autoGeneratedAlias = true;
        }
        if (secret != null) {
            operation.get(CredentialReference.CREDENTIAL_REFERENCE).get(CredentialReference.CLEAR_TEXT).set(secret);
        }
        ModelNode response = assertSuccess(services.executeOperation(operation)).get(RESULT);
        return validateResponse(response, secret, autoGeneratedAlias, exists);
    }

    private String validateResponse(ModelNode response, String secret, boolean autoGeneratedAlias, boolean exists) {
        if (secret == null) {
            assertFalse(response.isDefined());
            return null;
        }
        ModelNode credentialStoreUpdate = response.get(CredentialReference.CREDENTIAL_STORE_UPDATE);
        if (! exists) {
            assertTrue(credentialStoreUpdate.get(CredentialReference.STATUS).asString().equals(CredentialReference.NEW_ENTRY_ADDED));
        } else {
            assertTrue(credentialStoreUpdate.get(CredentialReference.STATUS).asString().equals(CredentialReference.EXISTING_ENTRY_UPDATED));
        }
        if (autoGeneratedAlias) {
            String generatedAlias = credentialStoreUpdate.get(CredentialReference.NEW_ALIAS).asString();
            assertTrue(generatedAlias != null && ! generatedAlias.isEmpty());
            return generatedAlias;
        }
        return null;
    }

    private String readAttribute(String keyStoreName, String attributeName) {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", keyStoreName);
        operation.get(ClientConstants.OP).set(ClientConstants.READ_ATTRIBUTE_OPERATION);
        operation.get(NAME).set(attributeName);
        return assertSuccess(services.executeOperation(operation)).get(RESULT).asStringOrNull();
    }

    private void removeKeyStore(String keyStoreName) {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store", keyStoreName);
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));
    }

    private CredentialStore getCredentialStore() {
        return getCredentialStore(NON_EMPTY_CS_NAME);
    }

    private CredentialStore getCredentialStore(String store) {
        ServiceName serviceName = Capabilities.CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(store);
        return (CredentialStore) services.getContainer().getService(serviceName).getValue();
    }

    private ModelNode assertSuccess(ModelNode response) {
        if (!response.get(OUTCOME).asString().equals(SUCCESS)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }

    private ModelNode assertFailed(ModelNode response) {
        if (! response.get(OUTCOME).asString().equals(FAILED)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }
}
