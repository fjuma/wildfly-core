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

        if (alias != null && secret != null) {
            final String parentName = PathAddress.pathAddress(operation.get(ModelDescriptionConstants.ADDRESS)).getLastElement().getValue();
            final String credentialStoreName = CredentialReference.credentialReferencePartAsStringIfDefined(resolvedValue, CredentialReference.STORE);
            CredentialStoreUpdateService service = (CredentialStoreUpdateService) context.getServiceRegistry(true).getRequiredService(CredentialStoreUpdateService.createServiceName(parentName, credentialStoreName)).getValue();
            try {
                service.updateCredentialStore(alias, secret);
            } catch (CredentialStoreException e) {
                throw new OperationFailedException(e);
            }
        }
        return ! operation.get(VALUE).equals(currentValue);
    }

    /*@Override
    protected boolean requiresRuntime(OperationContext context) {
        return !context.isBooting();
    }

    @Override
    protected void revertUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                         ModelNode valueToRestore, ModelNode valueToRevert, Void handback)
            throws OperationFailedException {
        System.out.println("sf");
    }*/
}
