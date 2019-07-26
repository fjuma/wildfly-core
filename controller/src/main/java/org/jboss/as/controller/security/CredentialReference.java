/*
 * JBoss, Home of Professional Open Source
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import static org.jboss.as.controller.logging.ControllerLogger.ROOT_LOGGER;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.StringTokenizer;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.AttributeMarshaller;
import org.jboss.as.controller.AttributeParser;
import org.jboss.as.controller.CapabilityReferenceRecorder;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.access.management.SensitiveTargetAccessConstraintDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.logging.ControllerLogger;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CommandCredentialSource;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.source.CredentialStoreCredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

/**
 * Utility class holding attribute definitions for credential-reference attribute in the model.
 * The class is unifying access to credentials defined through {@link org.wildfly.security.credential.store.CredentialStore}.
 *
 * It defines credential-reference attribute that other subsystems can use to reference external credentials of various
 * types.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class CredentialReference {

    public enum Version {
        VERSION_1_0, // clear-text and store mutually exclusive
        CURRENT // both clear-text and store allowed
    }

    /**
     * Capability required by a credential-reference attribute if its {@code store} field is configured.
     */
    public static final String CREDENTIAL_STORE_CAPABILITY = "org.wildfly.security.credential-store";
    /**
     * Standard name of a credential reference attribute.
     */
    public static final String CREDENTIAL_REFERENCE = "credential-reference";
    /**
     * Name of a field in the complex credential reference attribute.
     */
    public static final String STORE = "store";
    /**
     * Name of a field in the complex credential reference attribute.
     */
    public static final String ALIAS = "alias";
    /**
     * Name of a field in the complex credential reference attribute.
     */
    public static final String TYPE = "type";
    /**
     * Name of a field in the complex credential reference attribute.
     */
    public static final String CLEAR_TEXT = "clear-text";

    public static final String CREDENTIAL_STORE_UPDATE = "credential-store-update";

    public static final String NEW_ENTRY_ADDED = "new-entry-added";

    public static final String EXISTING_ENTRY_UPDATED = "existing-entry-updated";

    private static final SimpleAttributeDefinition credentialStoreAttribute;
    private static final SimpleAttributeDefinition credentialStoreAttribute_1_0;
    private static final SimpleAttributeDefinition credentialAliasAttribute;
    private static final SimpleAttributeDefinition credentialTypeAttribute;
    private static final SimpleAttributeDefinition clearTextAttribute;
    private static final SimpleAttributeDefinition clearTextAttribute_1_0;

    /** A variant that has a default capability reference configured for the attribute */
    private static final SimpleAttributeDefinition credentialStoreAttributeWithCapabilityReference_1_0;
    private static final SimpleAttributeDefinition credentialStoreAttributeWithCapabilityReference;

    private static final ObjectTypeAttributeDefinition credentialReferenceAD_1_0;
    private static final ObjectTypeAttributeDefinition credentialReferenceAD;

    /** Uses credentialStoreAttributeWithCapabilityReference */
    private static final ObjectTypeAttributeDefinition credentialReferenceADWithCapabilityReference_1_0;
    private static final ObjectTypeAttributeDefinition credentialReferenceADWithCapabilityReference;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    static {
        // clear-text and store mutually exclusive
        credentialStoreAttribute_1_0 = new SimpleAttributeDefinitionBuilder(STORE, ModelType.STRING, true)
                .setXmlName(STORE)
                .setRequires(ALIAS)
                .setAlternatives(CLEAR_TEXT)
                .build();

        clearTextAttribute_1_0 = new SimpleAttributeDefinitionBuilder(CLEAR_TEXT, ModelType.STRING, true)
                .setXmlName(CLEAR_TEXT)
                .setAllowExpression(true)
                .setAlternatives(STORE)
                .build();

        // both clear-text and store allowed
        credentialStoreAttribute = new SimpleAttributeDefinitionBuilder(STORE, ModelType.STRING, true)
                .setXmlName(STORE)
                .build();

        clearTextAttribute = new SimpleAttributeDefinitionBuilder(CLEAR_TEXT, ModelType.STRING, true)
                .setXmlName(CLEAR_TEXT)
                .setAllowExpression(true)
                .build();

        credentialAliasAttribute = new SimpleAttributeDefinitionBuilder(ALIAS, ModelType.STRING, true)
                .setXmlName(ALIAS)
                .setAllowExpression(true)
                .setRequires(STORE)
                .build();
        credentialTypeAttribute = new SimpleAttributeDefinitionBuilder(TYPE, ModelType.STRING, true)
                .setXmlName(TYPE)
                .setAllowExpression(true)
                .build();

        credentialReferenceAD_1_0 = getAttributeBuilder(CREDENTIAL_REFERENCE, CREDENTIAL_REFERENCE, false, false, Version.VERSION_1_0)
                .setRestartAllServices()
                .build();
        credentialReferenceAD = getAttributeBuilder(CREDENTIAL_REFERENCE, CREDENTIAL_REFERENCE, false, false)
                .setRestartAllServices()
                .build();

        credentialStoreAttributeWithCapabilityReference_1_0 = new SimpleAttributeDefinitionBuilder(credentialStoreAttribute_1_0)
                .setCapabilityReference(CREDENTIAL_STORE_CAPABILITY)
                .build();
        credentialStoreAttributeWithCapabilityReference = new SimpleAttributeDefinitionBuilder(credentialStoreAttribute)
                .setCapabilityReference(CREDENTIAL_STORE_CAPABILITY)
                .build();

        credentialReferenceADWithCapabilityReference_1_0 = getAttributeBuilder(CREDENTIAL_REFERENCE, CREDENTIAL_REFERENCE, false, true, Version.VERSION_1_0)
                .setRestartAllServices()
                .build();
        credentialReferenceADWithCapabilityReference = getAttributeBuilder(CREDENTIAL_REFERENCE, CREDENTIAL_REFERENCE, false, true)
                .setRestartAllServices()
                .build();
    }

    private CredentialReference() {
    }

    // utility static methods

    /**
     * Returns a definition for a credential reference attribute. The {@code store} field in the
     * attribute does not register any requirement for a credential store capability.
     *
     * @return credential reference attribute definition
     *
     */
    public static ObjectTypeAttributeDefinition getAttributeDefinition() {
        return getAttributeDefinition(Version.CURRENT);
    }

    /**
     * Returns a definition for a credential reference attribute. The {@code store} field in the
     * attribute does not register any requirement for a credential store capability.
     *
     * @param version the schema version to use
     * @return credential reference attribute definition
     *
     */
    public static ObjectTypeAttributeDefinition getAttributeDefinition(Version version) {
        if (version.equals(Version.VERSION_1_0)) {
            return credentialReferenceAD_1_0;
        } else {
            return credentialReferenceAD;
        }
    }


    /**
     * Returns a definition for a credential reference attribute, one that optionally
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) registers a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     *
     * @return credential reference attribute definition
     */
    public static ObjectTypeAttributeDefinition getAttributeDefinition(boolean referenceCredentialStore) {
        return getAttributeDefinition(referenceCredentialStore, Version.CURRENT);
    }

    /**
     * Returns a definition for a credential reference attribute, one that optionally
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) registers a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     * @param version the schema version to use
     * @return credential reference attribute definition
     */
    public static ObjectTypeAttributeDefinition getAttributeDefinition(boolean referenceCredentialStore, Version version) {
        if (version.equals(Version.VERSION_1_0)) {
            return referenceCredentialStore
                    ? credentialReferenceADWithCapabilityReference_1_0
                    : credentialReferenceAD_1_0;
        } else {
            return referenceCredentialStore
                    ? credentialReferenceADWithCapabilityReference
                    : credentialReferenceAD;
        }
    }


    /**
     * Gets an attribute builder for a credential-reference attribute with the standard {@code credential-reference}
     * attribute name, a configurable setting as to whether the attribute is required, and optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param allowNull whether the attribute is required
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(boolean allowNull, boolean referenceCredentialStore) {
        return getAttributeBuilder(allowNull, referenceCredentialStore, Version.CURRENT);
    }

    /**
     * Gets an attribute builder for a credential-reference attribute with the standard {@code credential-reference}
     * attribute name, a configurable setting as to whether the attribute is required, and optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param allowNull whether the attribute is required
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     * @param version the schema version to use
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(boolean allowNull, boolean referenceCredentialStore, Version version) {
        AttributeDefinition csAttr;
        if (version.equals(Version.VERSION_1_0)) {
            csAttr = referenceCredentialStore ? credentialStoreAttributeWithCapabilityReference_1_0 : credentialStoreAttribute_1_0;
        } else {
            csAttr = referenceCredentialStore ? credentialStoreAttributeWithCapabilityReference : credentialStoreAttribute;
        }
        return getAttributeBuilder(CREDENTIAL_REFERENCE, CREDENTIAL_REFERENCE, allowNull, csAttr, version);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics. The
     * {@code store} field in the attribute does not register any requirement for a credential store capability.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull) {
        return getAttributeBuilder(name, xmlName, allowNull, false, Version.CURRENT);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics. The
     * {@code store} field in the attribute does not register any requirement for a credential store capability.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @param version the schema version to use
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull, Version version) {
        return getAttributeBuilder(name, xmlName, allowNull, false, version);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics, optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName,
                                                                            boolean allowNull, boolean referenceCredentialStore) {
        return getAttributeBuilder(name, xmlName, allowNull, referenceCredentialStore, Version.CURRENT);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics, optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(String) register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     * If a requirement is registered, the dependent capability will be the single capability registered by the
     * resource that uses this attribute definition. The resource must expose one and only one capability in order
     * to use this facility.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @param referenceCredentialStore {@code true} if the {@code store} field in the
     *                                 attribute should register a requirement for a credential store capability.
     * @param version the schema version to use
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build an attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName,
                                                                            boolean allowNull, boolean referenceCredentialStore, Version version) {
        AttributeDefinition csAttr;
        if (version.equals(Version.VERSION_1_0)) {
            csAttr = referenceCredentialStore ? credentialStoreAttributeWithCapabilityReference_1_0 : credentialStoreAttribute_1_0;
        } else {
            csAttr = referenceCredentialStore ? credentialStoreAttributeWithCapabilityReference : credentialStoreAttribute;
        }
        return getAttributeBuilder(name, xmlName, allowNull, csAttr, version);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics, optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(CapabilityReferenceRecorder)} register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @param capabilityStoreReferenceRecorder a capability reference recorder that can record a requirement
     *                                         for the credential store referenced by the {@code store}
     *                                         field of the returned attribute definition. Can be {@code null},
     *                                         in which case no requirement would be recorded. If not {@code null}
     *                                         the recorder's
     *                                         {@link CapabilityReferenceRecorder#getBaseRequirementName() base requirement name}
     *                                         must equal {@link #CREDENTIAL_STORE_CAPABILITY}
     *
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull,
                                                                            CapabilityReferenceRecorder capabilityStoreReferenceRecorder) {
        return getAttributeBuilder(name, xmlName, allowNull, capabilityStoreReferenceRecorder, Version.CURRENT);
    }

    /**
     * Get an attribute builder for a credential-reference attribute with the specified characteristics, optionally configured to
     * {@link org.jboss.as.controller.AbstractAttributeDefinitionBuilder#setCapabilityReference(CapabilityReferenceRecorder)} register a requirement}
     * for a {@link #CREDENTIAL_STORE_CAPABILITY credential store capability}.
     *
     * @param name name of attribute
     * @param xmlName name of xml element
     * @param allowNull {@code false} if the attribute is required
     * @param capabilityStoreReferenceRecorder a capability reference recorder that can record a requirement
     *                                         for the credential store referenced by the {@code store}
     *                                         field of the returned attribute definition. Can be {@code null},
     *                                         in which case no requirement would be recorded. If not {@code null}
     *                                         the recorder's
     *                                         {@link CapabilityReferenceRecorder#getBaseRequirementName() base requirement name}
     *                                         must equal {@link #CREDENTIAL_STORE_CAPABILITY}
     *
     * @return an {@link ObjectTypeAttributeDefinition.Builder} which can be used to build attribute definition
     */
    public static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull,
                                                                            CapabilityReferenceRecorder capabilityStoreReferenceRecorder, Version version) {
        if (capabilityStoreReferenceRecorder == null) {
            return getAttributeBuilder(name, xmlName, allowNull, false, version);
        }

        assert CREDENTIAL_STORE_CAPABILITY.equals(capabilityStoreReferenceRecorder.getBaseRequirementName());
        AttributeDefinition csAttr = new SimpleAttributeDefinitionBuilder(version == Version.VERSION_1_0 ? credentialStoreAttribute_1_0 : credentialStoreAttribute)
                .setCapabilityReference(capabilityStoreReferenceRecorder)
                .build();
        return getAttributeBuilder(name, xmlName, allowNull, csAttr, version);
    }


    private static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull, AttributeDefinition credentialStoreDefinition) {
        return getAttributeBuilder(name, xmlName, allowNull, credentialStoreDefinition, Version.CURRENT);
    }

    private static ObjectTypeAttributeDefinition.Builder getAttributeBuilder(String name, String xmlName, boolean allowNull, AttributeDefinition credentialStoreDefinition, Version version) {
        return new ObjectTypeAttributeDefinition.Builder(name, credentialStoreDefinition, credentialAliasAttribute, credentialTypeAttribute,
                version == Version.VERSION_1_0 ? clearTextAttribute_1_0 : clearTextAttribute)
                .setXmlName(xmlName)
                .setAttributeMarshaller(AttributeMarshaller.ATTRIBUTE_OBJECT)
                .setAttributeParser(AttributeParser.OBJECT_PARSER)
                .setRequired(!allowNull)
                .setAccessConstraints(SensitiveTargetAccessConstraintDefinition.CREDENTIAL);
    }

    /**
     * Utility method to return part of {@link ObjectTypeAttributeDefinition} for credential reference attribute.
     *
     * {@see CredentialReference#getAttributeDefinition}
     * @param credentialReferenceValue value of credential reference attribute
     * @param name name of part to return (supported names: {@link #STORE} {@link #ALIAS} {@link #TYPE}
     *    {@link #CLEAR_TEXT}
     * @return value of part as {@link String}
     * @throws OperationFailedException when something goes wrong
     */
    public static String credentialReferencePartAsStringIfDefined(ModelNode credentialReferenceValue, String name) throws OperationFailedException {
        assert credentialReferenceValue.isDefined() : credentialReferenceValue;
        ModelNode result = credentialReferenceValue.get(name);
        if (result.isDefined()) {
            return result.asString();
        }
        return null;
    }

    /**
     * Get the ExceptionSupplier of {@link CredentialSource} which might throw an Exception while getting it.
     * {@link CredentialSource} is used later to retrieve the credential requested by configuration.
     *
     * @param context operation context
     * @param credentialReferenceAttributeDefinition credential-reference attribute definition
     * @param model containing the actual values
     * @param serviceBuilder of service which needs the credential
     * @return ExceptionSupplier of CredentialSource
     * @throws OperationFailedException wrapping exception when something goes wrong
     */
    public static ExceptionSupplier<CredentialSource, Exception> getCredentialSourceSupplier(OperationContext context, ObjectTypeAttributeDefinition credentialReferenceAttributeDefinition, ModelNode model, ServiceBuilder<?> serviceBuilder) throws OperationFailedException {
        ModelNode value = credentialReferenceAttributeDefinition.resolveModelAttribute(context, model);

        final String credentialStoreName;
        final String credentialAlias;
        final String credentialType;
        final String secret;

        if (value.isDefined()) {
            credentialStoreName = credentialReferencePartAsStringIfDefined(value, CredentialReference.STORE);
            credentialAlias = credentialReferencePartAsStringIfDefined(value, CredentialReference.ALIAS);
            credentialType = credentialReferencePartAsStringIfDefined(value, CredentialReference.TYPE);
            secret = credentialReferencePartAsStringIfDefined(value, CredentialReference.CLEAR_TEXT);
        } else {
            credentialStoreName = null;
            credentialAlias = null;
            credentialType = null;
            secret = null;
        }

        final ServiceRegistry serviceRegistry;
        final ServiceName credentialStoreServiceName;
        if (credentialAlias != null) {
            // use credential store service
            String credentialStoreCapabilityName = RuntimeCapability.buildDynamicCapabilityName(CREDENTIAL_STORE_CAPABILITY, credentialStoreName);
            credentialStoreServiceName = context.getCapabilityServiceName(credentialStoreCapabilityName, CredentialStore.class);
            if(serviceBuilder != null) {
                serviceBuilder.requires(credentialStoreServiceName);
            }
            serviceRegistry = context.getServiceRegistry(false);
        } else {
            credentialStoreServiceName = null;
            serviceRegistry = null;
        }

        return new ExceptionSupplier<CredentialSource, Exception>() {

            private String[] parseCommand(String command, String delimiter) {
                // comma can be back slashed
                final String[] parsedCommand = command.split("(?<!\\\\)" + delimiter);
                for (int k = 0; k < parsedCommand.length; k++) {
                    if (parsedCommand[k].indexOf('\\') != -1)
                        parsedCommand[k] = parsedCommand[k].replaceAll("\\\\" + delimiter, delimiter);
                }
                return parsedCommand;
            }

            private String stripType(String commandSpec) {
                StringTokenizer tokenizer = new StringTokenizer(commandSpec, "{}");
                tokenizer.nextToken();
                return tokenizer.nextToken();
            }

            /**
             * Gets a Credential Store Supplier.
             *
             * @return a supplier
             */
            @Override
            public CredentialSource get() throws Exception {
                if (credentialAlias != null) {
                    return new CredentialStoreCredentialSource(
                            () -> {
                                ServiceController<?> controller = serviceRegistry.getService(credentialStoreServiceName);
                                if (controller != null) {
                                    Service<CredentialStore> credentialStoreService = (Service<CredentialStore>) controller.getService();
                                    return credentialStoreService.getValue();
                                } else {
                                    return null;
                                }
                            }, credentialAlias);
                } else if (credentialType != null && credentialType.equalsIgnoreCase("COMMAND")) {
                    CommandCredentialSource.Builder command = CommandCredentialSource.builder();
                    String commandSpec = secret.trim();
                    String[] parts;
                    if (commandSpec.startsWith("{EXT")) {
                        parts = parseCommand(stripType(commandSpec), " ");  // space delimited
                    } else if (commandSpec.startsWith("{CMD")) {
                        parts = parseCommand(stripType(commandSpec), ",");  // comma delimited
                    } else {
                        parts = parseCommand(commandSpec, " ");
                    }
                    for(String part: parts) {
                        command.addCommand(part);
                    }
                    return command.build();
                } else if (secret != null && secret.startsWith("MASK-")) {
                    // simple MASK- string with PicketBox compatibility and fixed algorithm and initial key material
                    return new CredentialSource() {
                        @Override
                        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                            return credentialType == PasswordCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                        }

                        @Override
                        public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                            String[] part = secret.substring(5).split(";");  // strip "MASK-" and split by ';'
                            if (part.length != 3) {
                                throw ControllerLogger.ROOT_LOGGER.wrongMaskedPasswordFormat();
                            }
                            String salt = part[1];
                            final int iterationCount;
                            try {
                                iterationCount = Integer.parseInt(part[2]);
                            } catch (NumberFormatException e) {
                                throw ControllerLogger.ROOT_LOGGER.wrongMaskedPasswordFormat();
                            }
                            try {
                                PasswordBasedEncryptionUtil decryptUtil = new PasswordBasedEncryptionUtil.Builder()
                                        .picketBoxCompatibility()
                                        .salt(salt)
                                        .iteration(iterationCount)
                                        .decryptMode()
                                        .build();
                                return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR,
                                        decryptUtil.decodeAndDecrypt(part[0]))));
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }
                    };
                } else {
                    if (secret != null) {
                        // clear text password
                        return new CredentialSource() {
                            @Override
                            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                                return credentialType == PasswordCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                            }

                            @Override
                            public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                                return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray())));
                            }
                        };
                    } else {
                        return null;  // this indicates use of original method to get password from configuration
                    }
                }
            }
        };
    }

    /**
     * Get the ExceptionSupplier of {@link CredentialSource} which might throw an Exception while getting it.
     * {@link CredentialSource} is used later to retrieve the credential requested by configuration.
     *
     * @param context operation context
     * @param credentialReferenceAttributeDefinition credential-reference attribute definition
     * @param model containing the actual values
     * @param serviceBuilder of service which needs the credential
     * @param operation the operation
     * @return ExceptionSupplier of CredentialSource
     * @throws OperationFailedException wrapping exception when something goes wrong
     */
    public static ExceptionSupplier<CredentialSource, Exception> getCredentialSourceSupplier(OperationContext context, ObjectTypeAttributeDefinition credentialReferenceAttributeDefinition, ModelNode model, ServiceBuilder<?> serviceBuilder, ModelNode operation) throws OperationFailedException {
        ModelNode value = credentialReferenceAttributeDefinition.resolveModelAttribute(context, model);

        final String credentialStoreName;
        final String credentialAlias;
        final String credentialType;
        final String secret;

        if (value.isDefined()) {
            credentialStoreName = credentialReferencePartAsStringIfDefined(value, CredentialReference.STORE);
            credentialAlias = credentialReferencePartAsStringIfDefined(value, CredentialReference.ALIAS);
            credentialType = credentialReferencePartAsStringIfDefined(value, CredentialReference.TYPE);
            secret = credentialReferencePartAsStringIfDefined(operation.get(CREDENTIAL_REFERENCE), CredentialReference.CLEAR_TEXT);
        } else {
            credentialStoreName = null;
            credentialAlias = null;
            credentialType = null;
            secret = null;
        }

        final ServiceRegistry serviceRegistry;
        final ServiceName credentialStoreServiceName;
        if (credentialAlias != null) {
            // use credential store service
            String credentialStoreCapabilityName = RuntimeCapability.buildDynamicCapabilityName(CREDENTIAL_STORE_CAPABILITY, credentialStoreName);
            credentialStoreServiceName = context.getCapabilityServiceName(credentialStoreCapabilityName, CredentialStore.class);
            if(serviceBuilder != null) {
                serviceBuilder.requires(credentialStoreServiceName);

                String parent = PathAddress.pathAddress(operation.get(ModelDescriptionConstants.ADDRESS)).getLastElement().getValue();
                ServiceName credentialStoreUpdateServiceName = CredentialStoreUpdateService.createServiceName(parent, credentialStoreName);
                CredentialStoreUpdateService credentialStoreUpdateService = new CredentialStoreUpdateService(credentialAlias, secret, context.getResult().get(CREDENTIAL_STORE_UPDATE));
                ServiceBuilder<CredentialStoreUpdateService> credentialStoreUpdateServiceBuilder = context.getServiceTarget().addService(credentialStoreUpdateServiceName, credentialStoreUpdateService).setInitialMode(ServiceController.Mode.ACTIVE);
                credentialStoreUpdateServiceBuilder.addDependency(context.getCapabilityServiceName(credentialStoreCapabilityName, CredentialStore.class), CredentialStore.class, credentialStoreUpdateService.getCredentialStoreInjector());
                credentialStoreUpdateServiceBuilder.install();
                serviceBuilder.requires(credentialStoreUpdateServiceName);
                /*context.addStep((OperationContext context1, ModelNode operation1) -> {
                    CredentialStoreUpdateService service = (CredentialStoreUpdateService) context1.getServiceRegistry(true).getRequiredService(CredentialStoreUpdateService.createServiceName(parent, credentialStoreName)).getValue();
                    CredentialStoreUpdateService.CredentialStoreStatus status = service.getCredentialStoreStatus();
                    if (status == CredentialStoreUpdateService.CredentialStoreStatus.ENTRY_ADDED) {
                        context1.getResult().get(CREDENTIAL_STORE_UPDATE).set(NEW_ENTRY_ADDED);
                    } else if (status == CredentialStoreUpdateService.CredentialStoreStatus.ENTRY_UPDATED) {
                        context1.getResult().get(CREDENTIAL_STORE_UPDATE).set(EXISTING_ENTRY_UPDATED);
                    }
                }, OperationContext.Stage.RUNTIME, true);*/
            }
            serviceRegistry = context.getServiceRegistry(false);
        } else {
            credentialStoreServiceName = null;
            serviceRegistry = null;
        }

        return new ExceptionSupplier<CredentialSource, Exception>() {

            private String[] parseCommand(String command, String delimiter) {
                // comma can be back slashed
                final String[] parsedCommand = command.split("(?<!\\\\)" + delimiter);
                for (int k = 0; k < parsedCommand.length; k++) {
                    if (parsedCommand[k].indexOf('\\') != -1)
                        parsedCommand[k] = parsedCommand[k].replaceAll("\\\\" + delimiter, delimiter);
                }
                return parsedCommand;
            }

            private String stripType(String commandSpec) {
                StringTokenizer tokenizer = new StringTokenizer(commandSpec, "{}");
                tokenizer.nextToken();
                return tokenizer.nextToken();
            }

            /**
             * Gets a Credential Store Supplier.
             *
             * @return a supplier
             */
            @Override
            public CredentialSource get() throws Exception {
                if (credentialAlias != null) {
                    return new CredentialStoreCredentialSource(
                            () -> {
                                ServiceController<?> controller = serviceRegistry.getService(credentialStoreServiceName);
                                if (controller != null) {
                                    Service<CredentialStore> credentialStoreService = (Service<CredentialStore>) controller.getService();
                                    return credentialStoreService.getValue();
                                } else {
                                    return null;
                                }
                            }, credentialAlias);
                } else if (credentialType != null && credentialType.equalsIgnoreCase("COMMAND")) {
                    CommandCredentialSource.Builder command = CommandCredentialSource.builder();
                    String commandSpec = secret.trim();
                    String[] parts;
                    if (commandSpec.startsWith("{EXT")) {
                        parts = parseCommand(stripType(commandSpec), " ");  // space delimited
                    } else if (commandSpec.startsWith("{CMD")) {
                        parts = parseCommand(stripType(commandSpec), ",");  // comma delimited
                    } else {
                        parts = parseCommand(commandSpec, " ");
                    }
                    for(String part: parts) {
                        command.addCommand(part);
                    }
                    return command.build();
                } else if (secret != null && secret.startsWith("MASK-")) {
                    // simple MASK- string with PicketBox compatibility and fixed algorithm and initial key material
                    return new CredentialSource() {
                        @Override
                        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                            return credentialType == PasswordCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                        }

                        @Override
                        public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                            String[] part = secret.substring(5).split(";");  // strip "MASK-" and split by ';'
                            if (part.length != 3) {
                                throw ControllerLogger.ROOT_LOGGER.wrongMaskedPasswordFormat();
                            }
                            String salt = part[1];
                            final int iterationCount;
                            try {
                                iterationCount = Integer.parseInt(part[2]);
                            } catch (NumberFormatException e) {
                                throw ControllerLogger.ROOT_LOGGER.wrongMaskedPasswordFormat();
                            }
                            try {
                                PasswordBasedEncryptionUtil decryptUtil = new PasswordBasedEncryptionUtil.Builder()
                                        .picketBoxCompatibility()
                                        .salt(salt)
                                        .iteration(iterationCount)
                                        .decryptMode()
                                        .build();
                                return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR,
                                        decryptUtil.decodeAndDecrypt(part[0]))));
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }
                    };
                } else {
                    if (secret != null) {
                        // clear text password
                        return new CredentialSource() {
                            @Override
                            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                                return credentialType == PasswordCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                            }

                            @Override
                            public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                                return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray())));
                            }
                        };
                    } else {
                        return null;  // this indicates use of original method to get password from configuration
                    }
                }
            }
        };
    }

    static CredentialStore getCredentialStore(ServiceRegistry serviceRegistry, ServiceName credentialStoreServiceName) throws OperationFailedException {
        ServiceController<CredentialStore> controller = getRequiredService(serviceRegistry, credentialStoreServiceName, CredentialStore.class);
        ServiceController.State serviceState = controller.getState();
        if (serviceState != ServiceController.State.UP) {
            throw ROOT_LOGGER.requiredServiceNotUp(credentialStoreServiceName, serviceState);
        }
        return controller.getService().getValue();
    }

    static <T> ServiceController<T> getRequiredService(ServiceRegistry serviceRegistry, ServiceName serviceName, Class<T> serviceType) {
        ServiceController<?> controller = serviceRegistry.getRequiredService(serviceName);
        return (ServiceController<T>) controller;
    }

    static void storeSecret(CredentialStore credentialStore, String alias, String secretValue) throws CredentialStoreException {
        if (alias != null && secretValue != null) {
            char[] secret = secretValue != null ? secretValue.toCharArray() : new char[0];
            Password clearPassword = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret);
            credentialStore.store(alias, new PasswordCredential(clearPassword));
            try {
                credentialStore.flush();
            } catch (CredentialStoreException e) {
                // flush failed, remove the entry from the store to avoid an inconsistency between
                // the store on the FS and in the memory
                credentialStore.remove(alias, PasswordCredential.class);
                throw e;
            }
        }
    }

    public static void updateCredentialReference(ModelNode credentialReference) throws OperationFailedException {
        final String credentialStoreName;
        final String credentialType;
        final String secret;
        final String credentialAlias;

        if (credentialReference.isDefined()) {
            credentialStoreName = credentialReferencePartAsStringIfDefined(credentialReference, CredentialReference.STORE);
            credentialAlias = credentialReferencePartAsStringIfDefined(credentialReference, ALIAS);
            credentialType = credentialReferencePartAsStringIfDefined(credentialReference, CredentialReference.TYPE);
            secret = credentialReferencePartAsStringIfDefined(credentialReference, CLEAR_TEXT);
        } else {
            credentialStoreName = null;
            credentialAlias = null;
            credentialType = null;
            secret = null;
        }

        boolean removeSecret = false;
        if (credentialStoreName != null && secret != null) {
            if (credentialAlias != null) {
                removeSecret = true;
            } else if (! (credentialType != null && credentialType.equalsIgnoreCase("COMMAND")) && ! secret.startsWith("MASK-")) {
                credentialReference.get(ALIAS).set(generateAlias());
                removeSecret = true;
            }
            if (removeSecret) {
                credentialReference.get(CLEAR_TEXT).set(new ModelNode());
            }
        }
    }

    private static String generateAlias() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            int index = (int) (RANDOM.nextDouble() * CHARS.length());
            builder.append(CHARS.substring(index, index + 1));
        }
        return builder.toString();
    }
}
