/**
 * Copyright (C) 2011 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.connid.bundles.ad.sync;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.naming.ldap.LdapContext;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ad.ADConnector;
import net.tirasa.connid.bundles.ad.AnyObjectTest;
import net.tirasa.connid.bundles.ad.util.DirSyncUtils;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;

import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.impl.api.APIConfigurationImpl;
import org.identityconnectors.framework.impl.api.local.JavaClassProperties;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.Test;

public class SyncAnyObjectTestITCase extends AnyObjectTest {

    @Test
    public void syncFromTheBeginningWithNullToken() {
        // ----------------------------------
        // Handler specification
        // ----------------------------------
        final TestSyncResultsHandler handler = new TestSyncResultsHandler();
        // ----------------------------------

        // Ask just for description and serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Arrays.asList(new String[] {
            "description", "serialNumber" }));

        SyncToken previous = connector.sync(LdapSchema.ANY_OBJECT_CLASS, null, handler, oob.build());

        assertNotNull(previous);
        assertNotNull(previous.getValue());
        assertTrue(((byte[]) previous.getValue()).length > 0);

        Uid uid = connector.create(LdapSchema.ANY_OBJECT_CLASS, util.getSimpleProfile(util.getEntryIDs("123")), null);
        connector.delete(LdapSchema.ANY_OBJECT_CLASS, uid, null);
        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, null));

        SyncToken newly = connector.sync(LdapSchema.ANY_OBJECT_CLASS, previous, handler, oob.build());
        assertNotNull(newly);
        assertNotNull(newly.getValue());
        assertTrue(((byte[]) newly.getValue()).length > 0);

        assertFalse(Arrays.equals((byte[]) previous.getValue(), (byte[]) newly.getValue()));
    }

    @Test
    public void sync() {
        // We need to have several operation in the right sequence in order
        // to verify synchronization ...

        // ----------------------------------
        // Handler specification
        // ----------------------------------
        final TestSyncResultsHandler handler = new TestSyncResultsHandler();
        // ----------------------------------

        // Ask just for description and serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Arrays.asList(new String[] {
            "description", "serialNumber" }));

        SyncToken token = connector.getLatestSyncToken(LdapSchema.ANY_OBJECT_CLASS);
        connector.sync(LdapSchema.ANY_OBJECT_CLASS, token, handler, oob.build());

        assertTrue(handler.getDeleted().isEmpty());
        assertTrue(handler.getUpdated().isEmpty());

        handler.clear();

        final Map.Entry<String, String> ids11 = util.getEntryIDs("11");

        Uid uid11 = null;

        try {
            // ----------------------------------
            // check sync with new anyObject (token updated)
            // ----------------------------------
            // anyObject added sync
            uid11 = connector.create(LdapSchema.ANY_OBJECT_CLASS, util.getSimpleProfile(ids11), null);

            connector.sync(LdapSchema.ANY_OBJECT_CLASS, token, handler, oob.build());
            token = handler.getLatestReceivedToken();

            assertTrue(handler.getDeleted().isEmpty());

            // anyObject creation
            assertFalse(handler.getUpdated().isEmpty());

            for (SyncDelta usr : handler.getUpdated()) {
                final ConnectorObject obj = usr.getObject();
                assertEquals(ids11.getValue(), obj.getUid().getUidValue());

                // chek for returned attributes
                assertNotNull(obj.getAttributeByName("description"));
                assertNotNull(obj.getAttributeByName("serialNumber"));
                assertNotNull(obj.getAttributeByName("__NAME__"));
                assertNotNull(obj.getAttributeByName("__UID__"));
            }

            handler.clear();

            List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
                AttributeBuilder.build("description", "descriptionupdate")
            });

            uid11 = connector.update(LdapSchema.ANY_OBJECT_CLASS, uid11, new HashSet<>(attrToReplace), null);
            
            connector.sync(LdapSchema.ANY_OBJECT_CLASS, token, handler, oob.build());
            token = handler.getLatestReceivedToken();

            assertTrue(handler.getDeleted().isEmpty());
            assertEquals(1, handler.getUpdated().size());

            handler.clear();

            // check with updated token and without any modification
            connector.sync(LdapSchema.ANY_OBJECT_CLASS, token, handler, oob.build());

            assertTrue(handler.getDeleted().isEmpty());
            assertTrue(handler.getUpdated().isEmpty());
            // ----------------------------------
        } finally {
            if (uid11 != null) {
                // user delete sync
                conf.setRetrieveDeletedAnyObject(true);

                final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
                final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, conf);
                // TODO: remove the line below when using ConnId >= 1.4.0.1
                ((APIConfigurationImpl) impl).
                        setConfigurationProperties(JavaClassProperties.createConfigurationProperties(conf));

                final ConnectorFacade newConnector = factory.newInstance(impl);

                token = newConnector.getLatestSyncToken(LdapSchema.ANY_OBJECT_CLASS);

                newConnector.delete(LdapSchema.ANY_OBJECT_CLASS, uid11, null);

                handler.clear();

                newConnector.sync(LdapSchema.ANY_OBJECT_CLASS, token, handler, oob.build());

                assertFalse(handler.getDeleted().isEmpty());
                assertEquals(1, handler.getDeleted().size());
                assertTrue(handler.getDeleted().get(0).getUid().getUidValue().
                        startsWith(util.getEntryIDs("1").getValue()));
            }
        }
    }

    @Test
    public void verifyObjectGUID() {
        // Ask just for objectGUID
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("objectGUID"));

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS,
                new Uid(util.getEntryIDs("4").getValue()), oob.build());

        assertNotNull(object);

        final Attribute objectGUID = object.getAttributeByName("objectGUID");
        assertNotNull(objectGUID);
        assertNotNull(objectGUID.getValue());
        assertEquals(1, objectGUID.getValue().size());

        assertTrue(objectGUID.getValue().get(0) instanceof String);
        assertFalse(String.class.cast(objectGUID.getValue().get(0)).isEmpty());

        if (LOG.isOk()) {
            LOG.ok("ObjectGUID (String): {0}", objectGUID.getValue().get(0));
        }
    }

    @Test
    public void verifyFilter() {
        // instatiate a new configuration to avoid collisions with sync test
        final ADConfiguration configuration = getSimpleConf(PROP);

        final String DN = "CN=" + util.getEntryIDs("5").getKey() + "," + configuration.getAnyObjectBaseContexts()[0];

        final ADConnection connection = new ADConnection(configuration);
        final LdapContext ctx = connection.getInitialContext();

        assertTrue(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));

        configuration.setAccountSearchFilter("(&(Objectclass=device)(cn=" + util.getEntryIDs("5").getKey() + "))");
        assertTrue(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));

        configuration.setAccountSearchFilter("(&(Objectclass=device)(cn=" + util.getEntryIDs("6").getKey() + "))");
        assertFalse(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));
    }
}
