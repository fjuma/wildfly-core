/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.extension.elytron;

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.keystore.AliasFilter;
import org.wildfly.security.keystore.FilteringKeyStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A {@link Service} responsible for a single {@link KeyManager} instance.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class KeyManagerService implements Service<KeyManager> {

    private final InjectedValue<KeyStore> keyStoreInjector = new InjectedValue<>();
    final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();
    private final InjectedValue<ExceptionSupplier<CredentialSource, Exception>> credentialSourceSupplierInjector = new InjectedValue<>();
    private final String keyStoreName;
    private final String providerName;
    private final String algorithm;
    private final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier;
    private final String aliasFilter;
    private volatile KeyManager keyManager;

    KeyManagerService(String keyStoreName, String providerName, String algorithm, ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier, String aliasFilter) {
        this.keyStoreName = keyStoreName;
        this.providerName = providerName;
        this.algorithm = algorithm;
        this.credentialSourceSupplier = credentialSourceSupplier;
        this.aliasFilter = aliasFilter;
    }

    @Override
    public void start(StartContext startContext) throws StartException {
        Provider[] providers = providersInjector.getOptionalValue();
        KeyManagerFactory keyManagerFactory = null;
        if (providers != null) {
            for (Provider current : providers) {
                if (providerName == null || providerName.equals(current.getName())) {
                    try {
                        // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                        // However the same loop would need to remain as it is still possible a specific provider can't create it.
                        keyManagerFactory = KeyManagerFactory.getInstance(algorithm, current);
                        break;
                    } catch (NoSuchAlgorithmException ignored) {
                    }
                }
            }
            if (keyManagerFactory == null)
                throw ROOT_LOGGER.unableToCreateManagerFactory(KeyManagerFactory.class.getSimpleName(), algorithm);
        } else {
            try {
                keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new StartException(e);
            }
        }

        try {
            CredentialSource cs = credentialSourceSupplier.get();
            char[] password;
            if (cs != null) {
                password = cs.getCredential(PasswordCredential.class).getPassword(ClearPassword.class).getPassword();
            } else {
                throw new StartException(ROOT_LOGGER.keyStorePasswordCannotBeResolved(keyStoreName));
            }
            KeyStore keyStore = keyStoreInjector.getOptionalValue();
            if (aliasFilter != null) {
                keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
            }

            if (ROOT_LOGGER.isTraceEnabled()) {
                ROOT_LOGGER.tracef(
                        "KeyManager supplying:  providers = %s  provider = %s  algorithm = %s  keyManagerFactory = %s  " +
                                "keyStoreName = %s  aliasFilter = %s  keyStore = %s  keyStoreSize = %d  password (of item) = %b",
                        Arrays.toString(providers), providerName, algorithm, keyManagerFactory, keyStoreName, aliasFilter, keyStore, keyStore.size(), password != null
                );
            }

            keyManagerFactory.init(keyStore, password);
        } catch (StartException e) {
            throw e;
        } catch (Exception e) {
            throw new StartException(e);
        }

        SSLDefinitions.DelegatingKeyManager delegatingKeyManager = new SSLDefinitions.DelegatingKeyManager();
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        boolean foundKeyManager = false;
        for (KeyManager km : keyManagers) {
            if (km instanceof X509ExtendedKeyManager) {
                delegatingKeyManager.setKeyManager((X509ExtendedKeyManager) km);
                keyManager = delegatingKeyManager;
                foundKeyManager = true;
            }
        }
        if (! foundKeyManager) {
            throw ROOT_LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
        }
    }

    @Override
    public void stop(StopContext stopContext) {
        keyManager = null;
    }

    @Override
    public KeyManager getValue() throws IllegalStateException, IllegalArgumentException {
        return keyManager;
    }

    Injector<KeyStore> getKeyStoreInjector() {
        return keyStoreInjector;
    }

    Injector<ExceptionSupplier<CredentialSource, Exception>> getCredentialSourceSupplierInjector() {
        return credentialSourceSupplierInjector;
    }

    char[] resolveKeyPassword(KeyStoreService keyStoreService) throws RuntimeException {
        try {
            return keyStoreService.resolveKeyPassword(credentialSourceSupplierInjector.getOptionalValue());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
