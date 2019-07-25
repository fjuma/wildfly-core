/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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


package org.jboss.as.controller.security;

import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_UPDATE;
import static org.jboss.as.controller.security.CredentialReference.EXISTING_ENTRY_UPDATED;
import static org.jboss.as.controller.security.CredentialReference.NEW_ENTRY_ADDED;

import org.jboss.as.controller.OperationContext;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;


/**
 * A {@link Service} responsible for automatic updates of {@link CredentialStore}s.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */

public class CredentialStoreUpdateService implements Service<CredentialStoreUpdateService> {

    public enum CredentialStoreStatus {
        ENTRY_ADDED, ENTRY_UPDATED, NO_OP;
    }

    private String alias;
    private String secret;
    private CredentialStoreStatus credentialStoreStatus;
    private final OperationContext operationContext;

    private final InjectedValue<CredentialStore> injectedCredentialStore = new InjectedValue<>();

    CredentialStoreUpdateService(String alias, String secret) {
        this.alias = alias;
        this.secret = secret;
        this.operationContext = null;
    }

    CredentialStoreUpdateService(String alias, String secret, OperationContext operationContext) {
        this.alias = alias;
        this.secret = secret;
        this.operationContext = operationContext;
    }

    /*
     * Service Lifecycle Related Methods
     */


    @Override
    public void start(StartContext startContext) throws StartException {
        try {
            credentialStoreStatus = updateCredentialStore(alias, secret);
        } catch (CredentialStoreException e) {
            throw new StartException(e);
        }
    }

    @Override
    public void stop(StopContext stopContext) {
        this.alias = null;
        this.secret = null;
        this.credentialStoreStatus = null;
    }

    @Override
    public synchronized CredentialStoreUpdateService getValue() throws IllegalStateException, IllegalArgumentException {
        return this;
    }

    public CredentialStoreStatus updateCredentialStore(String alias, String secret) throws CredentialStoreException {
        if (alias != null && secret != null) {
            CredentialStore credentialStore = injectedCredentialStore.getValue();
            boolean exists = credentialStore.exists(alias, PasswordCredential.class);
            CredentialReference.storeSecret(credentialStore, alias, secret);
            if (exists) {
                operationContext.getResult().get(CREDENTIAL_STORE_UPDATE).set(EXISTING_ENTRY_UPDATED);
            } else {
                operationContext.getResult().get(CREDENTIAL_STORE_UPDATE).set(NEW_ENTRY_ADDED);
            }
            return exists ? CredentialStoreStatus.ENTRY_UPDATED : CredentialStoreStatus.ENTRY_ADDED;
        }
        return CredentialStoreStatus.NO_OP;
    }

    Injector<CredentialStore> getCredentialStoreInjector() {
        return injectedCredentialStore;
    }

    public static ServiceName createServiceName(String parentName, String credentialStoreName) {
        return ServiceName.of("org", "wildfly", "security", "elytron").append("credential-store-update", parentName + "-" + credentialStoreName);
    }

    public CredentialStoreStatus getCredentialStoreStatus () {
        return credentialStoreStatus;
    }

}
