/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.as.controller.security;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.VALUE;
import static org.jboss.as.controller.security.CredentialReference.ALIAS;
import static org.jboss.as.controller.security.CredentialReference.CLEAR_TEXT;
import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_REFERENCE;
import static org.jboss.as.controller.security.CredentialReference.updateCredentialReference;

import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.ReloadRequiredWriteAttributeHandler;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.wildfly.security.credential.store.CredentialStoreException;

public class CredentialReferenceWriteAttributeHandler extends ReloadRequiredWriteAttributeHandler {

    public CredentialReferenceWriteAttributeHandler(ObjectTypeAttributeDefinition attribute) {
        super(attribute);
    }

    @Override
    protected void finishModelStage(OperationContext context, ModelNode operation, String attributeName, ModelNode newValue,
                                    ModelNode oldValue, Resource resource) throws OperationFailedException {
        super.finishModelStage(context, operation, attributeName, newValue, oldValue, resource);
        updateCredentialReference(resource.getModel().get(CREDENTIAL_REFERENCE));
    }

    protected boolean applyUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                           ModelNode resolvedValue, ModelNode currentValue,
                                           HandbackHolder<Void> handbackHolder) throws OperationFailedException {
        final String alias = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, ALIAS);
        final String secret = CredentialReference.credentialReferencePartAsStringIfDefined(operation.get(VALUE), CLEAR_TEXT);

        final String parentName = PathAddress.pathAddress(operation.get(ModelDescriptionConstants.ADDRESS)).getLastElement().getValue();
        final String credentialStoreName = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, CredentialReference.STORE);
        CredentialStoreUpdateService service = (CredentialStoreUpdateService) context.getServiceRegistry(true).getRequiredService(CredentialStoreUpdateService.createServiceName(parentName, credentialStoreName)).getValue();
        try {
            service.updateCredentialStore(alias, secret);
        } catch (CredentialStoreException e) {
            throw new OperationFailedException(e);
        }
        return ! operation.get(VALUE).equals(currentValue);
    }

    /*@Override
    protected boolean applyUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                           ModelNode resolvedValue, ModelNode currentValue,
                                           HandbackHolder<Void> handbackHolder) throws OperationFailedException {
        //final ModelNode model = resource.getModel();
        //final ModelNode value = model.get(CREDENTIAL_REFERENCE);
        final String credentialStoreName;
        final String finalCredentialAlias;
        final String credentialType;
        final String secret;
        String credentialAlias;

        if (resolvedValue.isDefined()) {
            credentialStoreName = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, CredentialReference.STORE);
            credentialAlias = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, ALIAS);
            credentialType = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, CredentialReference.TYPE);
            secret = CredentialReference.credentialReferencePartAsStringIfDefined(operation.get(VALUE), CLEAR_TEXT);
        } else {
            credentialStoreName = null;
            credentialAlias = null;
            credentialType = null;
            secret = null;
        }

        boolean updateAlias = false;
        if (credentialStoreName != null && credentialAlias == null && secret != null && ! secret.startsWith("MASK-")) {
            credentialAlias = "myrandomalias";
            updateAlias = true;
        }
        finalCredentialAlias = credentialAlias;

        final ServiceRegistry serviceRegistry;
        final ServiceName credentialStoreServiceName;
        if (credentialStoreName != null) {
            // use credential store service
            String credentialStoreCapabilityName = RuntimeCapability.buildDynamicCapabilityName(CREDENTIAL_STORE_CAPABILITY, credentialStoreName);
            credentialStoreServiceName = context.getCapabilityServiceName(credentialStoreCapabilityName, CredentialStore.class);
            serviceRegistry = context.getServiceRegistry(false);

            if (finalCredentialAlias != null && secret != null) {
                CredentialStore credentialStore = CredentialReference.getCredentialStore(serviceRegistry, credentialStoreServiceName);
                try {
                    CredentialReference.storeSecret(credentialStore, finalCredentialAlias, secret);
                    // add generated alias to model
                    if (updateAlias) {
                        resolvedValue.get(ALIAS).set(finalCredentialAlias);
                    }

                    // remove clear-text password from the model
                    //resolvedValue.get(CLEAR_TEXT).set(new ModelNode());
                    //currentValue.get(CLEAR_TEXT).set(new ModelNode());
                    //context.readResource(PathAddress.EMPTY_ADDRESS).getModel().get(CREDENTIAL_REFERENCE).get(CLEAR_TEXT).set(new ModelNode());
                    *//*context.addStep((context1, operation1) -> {
                        operation.get(ModelDescriptionConstants.VALUE).get(CLEAR_TEXT).set(new ModelNode());
                    }, OperationContext.Stage.RUNTIME);*//*
                } catch (CredentialStoreException e) {
                    throw new OperationFailedException(e);
                }
                *//*if (updateAlias) {
                    model.get(CREDENTIAL_REFERENCE).get(ALIAS).set(finalCredentialAlias);
                }
                model.get(CREDENTIAL_REFERENCE).get(CLEAR_TEXT).set(new ModelNode());
                /*CredentialStore credentialStore = getCredentialStore(serviceRegistry, credentialStoreServiceName);
                try {
                    storeSecret(credentialStore, finalCredentialAlias, secret);
                    // add generated alias to model
                    if (updateAlias) {
                        model.get(CREDENTIAL_REFERENCE).get(ALIAS).set(finalCredentialAlias);
                    }

                    // remove clear-text password from the model
                    model.get(CREDENTIAL_REFERENCE).get(CLEAR_TEXT).set(new ModelNode());
                } catch (CredentialStoreException e) {
                    throw new OperationFailedException(e);
                }*//*
                *//*if (updateAlias) {
                    model.get(CREDENTIAL_REFERENCE).get(ALIAS).set(finalCredentialAlias);
                }
                model.get(CREDENTIAL_REFERENCE).get(CLEAR_TEXT).set(new ModelNode());*//*
                //ModelNode writeAttributeOperation = Util.getWriteAttributeOperation(context.getCurrentAddress(), CredentialReference.CREDENTIAL_REFERENCE + "." + CredentialReference.ALIAS, finalCredentialAlias);
                //final OperationStepHandler writeHandler = context.getRootResourceRegistration().getSubModel(context.getCurrentAddress()).getOperationHandler(PathAddress.EMPTY_ADDRESS, WRITE_ATTRIBUTE_OPERATION);
                //context.addStep(writeAttributeOperation, writeHandler, OperationContext.Stage.RUNTIME);

                //OperationEntry entry = context.getRootResourceRegistration().getOperationEntry(context.getCurrentAddress(), WRITE_ATTRIBUTE_OPERATION);
                //context.addModelStep(entry.getOperationDefinition(), entry.getOperationHandler(), true);

            }
        } else {
            credentialStoreServiceName = null;
            serviceRegistry = null;
        }
        return false;
    }*/

    @Override
    protected boolean requiresRuntime(OperationContext context) {
        return !context.isBooting();
    }

    @Override
    protected void revertUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                         ModelNode valueToRestore, ModelNode valueToRevert, Void handback)
            throws OperationFailedException {
        System.out.println("sf");
    }
}
