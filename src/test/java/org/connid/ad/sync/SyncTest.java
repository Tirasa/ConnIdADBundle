/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2011 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License. You can obtain
 * a copy of the License at https://glassfish.dev.java.net/public/CDDL+GPL.html
 * or glassfish/bootstrap/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/bootstrap/legal/LICENSE.txt.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.  If applicable, add the following below the License
 * Header, with the fields enclosed by brackets [] replaced by your own
 * identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 */
package org.connid.ad.sync;

import java.util.ArrayList;
import java.util.Arrays;
import javax.naming.NamingException;
import org.identityconnectors.framework.common.objects.SyncDelta;
import static org.junit.Assert.*;

import java.util.Collections;
import java.util.List;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;
import org.connid.ad.ADConfiguration;
import org.connid.ad.ADConnection;
import org.connid.ad.ADConnector;
import org.connid.ad.AbstractTest;
import org.connid.ad.util.DirSyncUtils;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class SyncTest extends AbstractTest {

    @BeforeClass
    public static void init() {
        init(SyncTest.class.getSimpleName());
    }

    @Test
    public void sync() {
        // We need to have several operation in the right sequence in order
        // to verify synchronization ...

        // ----------------------------------
        // Handler specification
        // ----------------------------------

        final List<SyncDelta> updated = new ArrayList<SyncDelta>();
        final List<SyncDelta> deleted = new ArrayList<SyncDelta>();

        final SyncResultsHandler hundler = new SyncResultsHandler() {

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
        oob.setAttributesToGet(
                Arrays.asList(new String[]{"sAMAccountName", "givenName"}));

        SyncToken token = null;

        // ----------------------------------
        // check sync without modification and deleted users (token: null)
        // ----------------------------------
        connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
        token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

        // deleted set could not be verified now beacause someone could have
        // manually upadated the member attribute of a specified group
        assertFalse(updated.isEmpty());

        // Since DirSync search is paginated we must loop on sync until returned
        // handles will be empty
        while (!updated.isEmpty() || !deleted.isEmpty()) {

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);
        }

        updated.clear();
        deleted.clear();

        // Check with updated token without any modification
        connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
        token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

        assertTrue(deleted.isEmpty());
        assertTrue(updated.isEmpty());
        // ----------------------------------

        final String CN11 = SyncTest.class.getSimpleName() + "11";
        final String CN12 = SyncTest.class.getSimpleName() + "12";

        Uid uid11 = null;
        Uid uid12 = null;

        try {
            // ----------------------------------
            // check sync with new user (token updated)
            // ----------------------------------
            // user added sync
            uid11 = connector.create(
                    ObjectClass.ACCOUNT, getSimpleProfile(CN11), null);

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            // user ccreation and group modification
            assertEquals(3, updated.size());

            // chek for returned attributes
            assertEquals(4, updated.get(0).getObject().getAttributes().size());
            final ConnectorObject obj = updated.get(0).getObject();
            assertNotNull(obj.getAttributeByName("sAMAccountName"));
            assertNotNull(obj.getAttributeByName("givenName"));
            assertNotNull(obj.getAttributeByName("__NAME__"));
            assertNotNull(obj.getAttributeByName("__UID__"));
            assertEquals("SAAN_" + CN11, updated.get(0).getUid().getUidValue());

            updated.clear();
            deleted.clear();

            // check with updated token and without any modification
            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            assertTrue(updated.isEmpty());
            // ----------------------------------

            // ----------------------------------
            // check sync with user 'IN' group (token updated)
            // ----------------------------------
            // created a new user without memberships specification
            final ADConfiguration configuration = getSimpleConf(prop);
            configuration.setMemberships();

            if (LOG.isOk()) {
                LOG.ok("\n Configuration: {0}\n Filter: {1}",
                        configuration,
                        DirSyncUtils.createLdapFilter(configuration));
            }

            final ADConnection connection = new ADConnection(configuration);
            final LdapContext ctx = connection.getInitialContext();

            final Attributes attrs = new BasicAttributes(true);
            attrs.put(new BasicAttribute("cn", CN12));
            attrs.put(new BasicAttribute("sn", CN12));
            attrs.put(new BasicAttribute("givenName", CN12));
            attrs.put(new BasicAttribute("displayName", CN12));
            attrs.put(new BasicAttribute("sAMAccountName", "SAAN_" + CN12));
            attrs.put(new BasicAttribute("userPrincipalName", "test@test.org"));
            attrs.put(new BasicAttribute("userPassword", "password"));
            attrs.put(new BasicAttribute("objectClass", "top"));
            attrs.put(new BasicAttribute("objectClass", "person"));
            attrs.put(new BasicAttribute("objectClass", "organizationalPerson"));
            attrs.put(new BasicAttribute("objectClass", "user"));

            try {
                ctx.createSubcontext(
                        "CN=" + CN12 + "," + configuration.getBaseContexts()[0],
                        attrs);

                uid12 = new Uid("SAAN_" + CN12);
            } catch (NamingException e) {
                LOG.error(e, "Error creating user {0}", CN12);
                assert (false);
            }

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            assertTrue(updated.isEmpty());

            ModificationItem[] mod = new ModificationItem[]{
                new ModificationItem(
                DirContext.ADD_ATTRIBUTE, new BasicAttribute(
                "member",
                "CN=" + CN12 + "," + configuration.getBaseContexts()[0]))
            };

            try {
                ctx.modifyAttributes(conf.getMemberships()[0], mod);
            } catch (NamingException e) {
                LOG.error(e, "Error adding membership to {0}", CN12);
                assert (false);
            }

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            assertEquals(1, updated.size());
            // ----------------------------------

            // ----------------------------------
            // check sync with user 'OUT' group (token updated)
            // ----------------------------------
            mod = new ModificationItem[]{
                new ModificationItem(
                DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(
                "member",
                "CN=" + CN12 + "," + configuration.getBaseContexts()[0]))
            };

            try {
                ctx.modifyAttributes(conf.getMemberships()[0], mod);
            } catch (NamingException e) {
                LOG.error(e, "Error adding membership to {0}", CN12);
                assert (false);
            }

            updated.clear();
            deleted.clear();


            // sync user delete (member out is like a user delete)
            conf.setRetrieveDeletedUser(true);

            final ConnectorFacadeFactory factory =
                    ConnectorFacadeFactory.getInstance();

            final APIConfiguration impl =
                    TestHelpers.createTestConfiguration(
                    ADConnector.class, conf);

            final ConnectorFacade newConnector = factory.newInstance(impl);

            newConnector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = newConnector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(updated.isEmpty());
            assertEquals(1, deleted.size());
            // ----------------------------------

            // ----------------------------------
            // check sync with updated user (token updated)
            // ----------------------------------
            // user modify sync
            uid11 = connector.update(
                    ObjectClass.ACCOUNT, uid11,
                    Collections.singleton(AttributeBuilder.build(
                    "givenName", Collections.singleton("changed"))),
                    null);

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            assertEquals(1, updated.size());

            updated.clear();
            deleted.clear();

            // check with updated token and without any modification
            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            assertTrue(updated.isEmpty());
            // ----------------------------------
        } finally {
            if (uid12 != null) {
                connector.delete(ObjectClass.ACCOUNT, uid12, null);
            }

            if (uid11 != null) {
                // user delete sync
                conf.setRetrieveDeletedUser(true);

                final ConnectorFacadeFactory factory =
                        ConnectorFacadeFactory.getInstance();

                final APIConfiguration impl =
                        TestHelpers.createTestConfiguration(
                        ADConnector.class, conf);

                final ConnectorFacade newConnector = factory.newInstance(impl);

                newConnector.delete(ObjectClass.ACCOUNT, uid11, null);

                updated.clear();
                deleted.clear();

                newConnector.sync(
                        ObjectClass.ACCOUNT, token, hundler, oob.build());

                assertFalse(deleted.isEmpty());
                assertTrue(deleted.size() <= 2);
                assertTrue(deleted.get(0).getUid().getUidValue().startsWith(
                        "SAAN_" + SyncTest.class.getSimpleName() + "1"));
            }
        }
    }

    @Test
    public void initialLoading() {
        // We need to have several operation in the right sequence in order
        // to verify synchronization ...

        // ----------------------------------
        // Handler specification
        // ----------------------------------

        final List<SyncDelta> updated = new ArrayList<SyncDelta>();
        final List<SyncDelta> deleted = new ArrayList<SyncDelta>();

        final SyncResultsHandler hundler = new SyncResultsHandler() {

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
        oob.setAttributesToGet(
                Arrays.asList(new String[]{"sAMAccountName", "givenName"}));

        SyncToken token = null;

        conf.setRetrieveDeletedUser(false);
        conf.setLoading(true);

        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        APIConfiguration impl = TestHelpers.createTestConfiguration(
                ADConnector.class, conf);

        ConnectorFacade newConnector = factory.newInstance(impl);

        // ----------------------------------
        // check initial loading
        // ----------------------------------
        newConnector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
        token = newConnector.getLatestSyncToken(ObjectClass.ACCOUNT);

        assertFalse(updated.isEmpty());
        assertTrue(deleted.isEmpty());

        // Since DirSync search is paginated we must loop on sync until returned
        // handles will be empty
        while (!updated.isEmpty() || !deleted.isEmpty()) {
            updated.clear();
            deleted.clear();

            newConnector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = newConnector.getLatestSyncToken(ObjectClass.ACCOUNT);
        }

        // ----------------------------------
        // check sync with new user (token updated)
        // ----------------------------------conf.setRetrieveDeletedUser(false);
        conf.setLoading(false);

        factory = ConnectorFacadeFactory.getInstance();
        impl = TestHelpers.createTestConfiguration(ADConnector.class, conf);
        newConnector = factory.newInstance(impl);

        final String CN13 = SyncTest.class.getSimpleName() + "13";

        Uid uid13 = null;

        try {
            // user added sync
            uid13 = connector.create(
                    ObjectClass.ACCOUNT, getSimpleProfile(CN13), null);

            updated.clear();
            deleted.clear();

            connector.sync(ObjectClass.ACCOUNT, token, hundler, oob.build());
            token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);

            assertTrue(deleted.isEmpty());
            // user ccreation and group modification
            assertEquals(3, updated.size());
        } finally {
            if (uid13 != null) {
                connector.delete(ObjectClass.ACCOUNT, uid13, null);
            }
        }
        // ----------------------------------
    }

    @Test
    public void verifyObjectGUID() {
        String SAAN = "SAAN_" + SyncTest.class.getSimpleName() + "4";

        // Ask just for objectGUID
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("objectGUID"));

        final ConnectorObject object = connector.getObject(
                ObjectClass.ACCOUNT, new Uid(SAAN), oob.build());

        assertNotNull(object);

        final Attribute objectGUID = object.getAttributeByName("objectGUID");
        assertNotNull(objectGUID);
        assertNotNull(objectGUID.getValue());
        assertEquals(1, objectGUID.getValue().size());

        final String guid = DirSyncUtils.getGuidAsString(
                (byte[]) objectGUID.getValue().get(0));
        assertNotNull(guid);

        if (LOG.isOk()) {
            LOG.ok("ObjectGUID (String): {0}", guid);
        }
    }

    @Test
    public void verifyFilter() {
        // instatiate a new configuration to avoid collisions with sync test
        final ADConfiguration configuration = getSimpleConf(prop);

        final String DN = "CN=" + SyncTest.class.getSimpleName() + "5,"
                + configuration.getBaseContexts()[0];

        final ADConnection connection = new ADConnection(configuration);
        final LdapContext ctx = connection.getInitialContext();

        assertTrue(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));

        configuration.setAccountSearchFilter("(&(Objectclass=user)"
                + "(cn=" + SyncTest.class.getSimpleName() + "5))");

        assertTrue(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));

        configuration.setAccountSearchFilter("(&(Objectclass=user)"
                + "(cn=" + SyncTest.class.getSimpleName() + "6))");

        assertFalse(DirSyncUtils.verifyCustomFilter(ctx, DN, configuration));
    }

    @AfterClass
    public static void cleanup() {
        cleanup(SyncTest.class.getSimpleName());
    }
}
