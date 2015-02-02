/* 
 * Copyright 2015 ConnId.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connid.bundles.ad.sync;

import static org.junit.Assert.*;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.GroupTest;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.Test;

public class SyncGroupTest extends GroupTest {

    @Test
    public void sync() {
        // We need to have several operation in the right sequence in order to verify synchronization ...

        // ----------------------------------
        // Handler specification
        // ----------------------------------
        final List<SyncDelta> updated = new ArrayList<SyncDelta>();
        final List<SyncDelta> deleted = new ArrayList<SyncDelta>();

        final SyncResultsHandler handler = new SyncResultsHandler() {

            @Override
            public boolean handle(final SyncDelta sd) {
                if (sd.getDeltaType() == SyncDeltaType.DELETE) {
                    return deleted.add(sd);
                } else {
                    return updated.add(sd);
                }
            }
        };
        // ----------------------------------

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Arrays.asList(new String[] { "sAMAccountName", "member" }));

        SyncToken token = connector.getLatestSyncToken(ObjectClass.GROUP);

        // ----------------------------------
        // check sync without modification and deleted groups (token: null)
        // ----------------------------------
        connector.sync(ObjectClass.GROUP, token, handler, oob.build());

        assertTrue(deleted.isEmpty());
        assertTrue(updated.isEmpty());

        final Map.Entry<String, String> ids11 = util.getEntryIDs("11");

        Uid uid11 = null;
        Uid groupTestFor11 = null;

        try {
            // ----------------------------------
            // check sync with new group (token updated)
            // ----------------------------------
            // group added sync
            SyncToken nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            uid11 = connector.create(ObjectClass.GROUP, util.getSimpleProfile(ids11), null);
            token = nextToken;

            updated.clear();
            deleted.clear();

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            // group related to uid11 memberOf (it doesn't match the filter) 
            assertEquals(1, deleted.size());

            // group and memberships (update from member update of GroupTestInFilter and the group itself) creation
            assertEquals(3, updated.size());

            final ConnectorObject obj = updated.get(0).getObject();

            // chek for returned attributes
            assertEquals(4, updated.get(0).getObject().getAttributes().size());
            assertNotNull(obj.getAttributeByName("sAMAccountName"));
            assertNotNull(obj.getAttributeByName("__NAME__"));
            assertNotNull(obj.getAttributeByName("__UID__"));
            assertNotNull(obj.getAttributeByName("member"));
            assertEquals(ids11.getValue(), updated.get(0).getUid().getUidValue());

            updated.clear();
            deleted.clear();

            // check with updated token and without any modification
            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            assertTrue(deleted.isEmpty());
            assertTrue(updated.isEmpty());
            // ----------------------------------

            // ----------------------------------
            // check sync with group 'IN' group (token updated)
            // ----------------------------------
            // created a new user without memberships specification
            final ADConfiguration configuration = getSimpleConf(prop);

            final ADConnection connection = new ADConnection(configuration);
            final LdapContext ctx = connection.getInitialContext();

            final Attributes attrs = new BasicAttributes(true);
            attrs.put(new BasicAttribute("cn", "GroupTestFor11"));
            attrs.put(new BasicAttribute("sAMAccountName", "GroupTestFor11"));
            attrs.put(new BasicAttribute("objectClass", "top"));
            attrs.put(new BasicAttribute("objectClass", "group"));

            try {

                ctx.createSubcontext("CN=GroupTestFor11,CN=Users," + configuration.getUserBaseContexts()[0], attrs);
                groupTestFor11 = new Uid("GroupTestFor11");

            } catch (NamingException e) {
                LOG.error(e, "Error creating user GroupTestFor11");
                assert (false);
            }

            updated.clear();
            deleted.clear();

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            assertFalse(deleted.isEmpty());
            assertTrue(updated.isEmpty());

            ModificationItem[] mod = new ModificationItem[] {
                new ModificationItem(
                DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("member", "CN=GroupTestFor11,CN=Users," + configuration.getUserBaseContexts()[0]))
            };

            try {
                ctx.modifyAttributes(util.getEntryDN(util.getEntryIDs("InFilter").getKey(), ObjectClass.GROUP), mod);
            } catch (NamingException e) {
                LOG.error(e, "Error adding membership for newMemberFor11");
                assert (false);
            }

            updated.clear();
            deleted.clear();

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            // group related to uid11 memberOf (it doesn't match the filter) 
            assertEquals(1, deleted.size());

            // group in
            assertEquals(1, updated.size());
            // ----------------------------------

            // ----------------------------------
            // check sync with user 'OUT' group (token updated)
            // ----------------------------------
            mod = new ModificationItem[] {
                new ModificationItem(
                DirContext.REMOVE_ATTRIBUTE,
                new BasicAttribute("member", "CN=GroupTestFor11,CN=Users," + configuration.getUserBaseContexts()[0]))
            };

            try {
                ctx.modifyAttributes(util.getEntryDN(util.getEntryIDs("InFilter").getKey(), ObjectClass.GROUP), mod);
            } catch (NamingException e) {
                LOG.error(e, "Error adding membership for GroupTestFor11");
                assert (false);
            }

            updated.clear();
            deleted.clear();

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            assertEquals(2, deleted.size());
            assertTrue(updated.isEmpty());
            // ----------------------------------

            // ----------------------------------
            // Check for group which doesn't match the specified group search filter
            // ----------------------------------
            updated.clear();
            deleted.clear();

            Map.Entry<String, String> ids = new AbstractMap.SimpleEntry<String, String>("grptmp", "grptmp");
            final Uid uid = connector.create(ObjectClass.GROUP, util.getSimpleProfile(ids), null);
            assertNotNull(uid);

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            assertFalse(deleted.isEmpty());
            assertTrue(updated.isEmpty());

            connector.delete(ObjectClass.GROUP, uid, null);

            nextToken = connector.getLatestSyncToken(ObjectClass.GROUP);
            connector.sync(ObjectClass.GROUP, token, handler, oob.build());
            token = nextToken;

            // always returned
            assertFalse(deleted.isEmpty());
            assertTrue(updated.isEmpty());

            // ----------------------------------
        } catch (Throwable t) {
            LOG.error(t, "Unexpected exception");
            assert (false);
        } finally {
            assertNotNull(uid11);
            connector.delete(ObjectClass.GROUP, uid11, null);

            assertNotNull(groupTestFor11);
            connector.delete(ObjectClass.GROUP, groupTestFor11, null);

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.GROUP, token, handler, oob.build());

            assertEquals(2, deleted.size());
            assertTrue(updated.isEmpty());
        }
    }
}
