/**
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2011-2013 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License"). You may not use this file
 * except in compliance with the License.
 *
 * You can obtain a copy of the License at https://oss.oracle.com/licenses/CDDL
 * See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at https://oss.oracle.com/licenses/CDDL.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.connid.bundles.ad.crud;

import static org.junit.Assert.*;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnector;
import org.connid.bundles.ad.TestUtil;
import org.connid.bundles.ad.UserTest;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.Test;

public class UserCrudTest extends UserTest {

    @Test
    public void search() {

        final Map.Entry<String, String> ids = util.getEntryIDs("1");

        // create filter 
        final Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("sAMAccountName", ids.getValue()));

        // create results handler
        final List<Attribute> results = new ArrayList<Attribute>();
        final ResultsHandler handler = new ResultsHandler() {

            @Override
            public boolean handle(ConnectorObject co) {
                return results.add(co.getAttributeByName("sAMAccountName"));
            }
        };

        // create options for returning attributes
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("sAMAccountName"));

        connector.search(ObjectClass.ACCOUNT, filter, handler, oob.build());

        assertEquals(1, results.size());
        assertEquals(Collections.singletonList(ids.getValue()), results.get(0).getValue());
    }

    @Test
    public void read() {
        final Map.Entry<String, String> ids = util.getEntryIDs("2");

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("sAMAccountName");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: sAMAccountName, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("sAMAccountName"));
        assertEquals(Collections.singletonList(ids.getValue()), object.getAttributeByName("sAMAccountName").getValue());
    }

    @Test
    public void create() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("11");

        assertNull("Please remove user 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids);

        final Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Arrays.asList("memberOf", "userAccountControl"));

        // retrieve created object
        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // check for memberOf attribute     
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));
        assertNotNull(object.getAttributeByName("userAccountControl"));

        final Set<String> expected = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        expected.addAll(Arrays.asList(conf.getMemberships()));

        final Set<String> actual = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Object dn : object.getAttributeByName("memberOf").getValue()) {
            actual.add(dn.toString());
        }

        assertEquals(expected, actual);
        assertEquals(ids.getValue(), object.getUid().getUidValue());
        assertEquals(
                util.getEntryDN(ids.getKey(), ObjectClass.ACCOUNT).toLowerCase(),
                object.getName().getNameValue().toLowerCase());

        final Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
    }

    @Test
    public void createWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("nodn11");

        assertNull("Please remove user 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids, false);

        final Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf");

        // retrieve created object
        final ConnectorObject object =
                connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // check for memberOf attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));

        final Set<String> expected = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        expected.addAll(Arrays.asList(conf.getMemberships()));

        final Set<String> actual = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Object dn : object.getAttributeByName("memberOf").getValue()) {
            actual.add(dn.toString());
        }

        assertEquals(expected, actual);
        assertEquals(ids.getValue(), object.getUid().getUidValue());
        assertEquals(
                util.getEntryDN(ids.getKey(),
                ObjectClass.ACCOUNT).toLowerCase(), object.getName().getNameValue().toLowerCase());

        final Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
    }

    @Test
    public void checkLdapGroups() {
        assertNotNull(connector);
        assertNotNull(conf);

        String baseContext = prop.getProperty("baseContext");

        final Map.Entry<String, String> ids = util.getEntryIDs("20");

        assertNull("Please remove user 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids, false);

        final Attribute ldapGroups = AttributeUtil.find("ldapGroups", attributes);
        attributes.remove(ldapGroups);

        final List<String> groupsToBeAdded = new ArrayList<String>();

        if (ldapGroups != null && ldapGroups.getValue() != null) {
            for (Object obj : ldapGroups.getValue()) {
                groupsToBeAdded.add(obj.toString());
            }
        }

        groupsToBeAdded.add("CN=Cert Publishers,CN=Users," + baseContext);
        groupsToBeAdded.add("CN=Schema Admins,CN=Users," + baseContext);

        attributes.add(AttributeBuilder.build("ldapGroups", groupsToBeAdded));

        Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf", "ldapGroups");

        // retrieve created object
        ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // check for memberOf attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build("ldapGroups", "CN=Schema Admins,CN=Users," + baseContext) });

        uid = connector.update(
                ObjectClass.ACCOUNT,
                uid,
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("ldapGroups",
            "CN=Schema Admins,CN=Users," + baseContext,
            "CN=Cert Publishers,CN=Users," + baseContext) });

        uid = connector.update(
                ObjectClass.ACCOUNT,
                uid,
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
    }

    @Test
    public void update() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("3");

        Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        try {
            connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    ids.getValue(), // uid
                    new GuardedString("Password321".toCharArray()), // password
                    null);
            fail();
        } catch (ConnectorException ignore) {
            // ignore
        }

        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build("givenName", "gnupdate"),
            AttributeBuilder.buildPassword(
            new GuardedString("Password321".toCharArray())) });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(ids.getValue()),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("givenName");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: givenName, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("givenName"));
        assertEquals(
                Collections.singletonList("gnupdate"),
                object.getAttributeByName("givenName").getValue());

        try {
            connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    ids.getValue(), // uid
                    new GuardedString("Password123".toCharArray()), // password
                    null);
            fail();
        } catch (ConnectorException ignore) {
            // ignore
        }

        authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password321".toCharArray()), // password
                null);

        assertNotNull(authUid);

        // --------------------------
        // force change password
        // --------------------------
        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("pwdLastSet", true) });

        connector.update(
                ObjectClass.ACCOUNT,
                new Uid(ids.getValue()),
                new HashSet<Attribute>(attrToReplace),
                null);

        try {
            connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    ids.getValue(), // uid
                    new GuardedString("Password123".toCharArray()), // password
                    null);
            fail();
        } catch (ConnectorException ignore) {
            // ignore
        }
        // --------------------------
    }

    @Test
    public void rename() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");


        final String DN = "cn=" + ids.getKey() + ",cn=Computers," + BASE_CONTEXT;

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, DN),
            AttributeBuilder.buildPassword(new GuardedString("Password321".toCharArray())) });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        uid = connector.authenticate(
                ObjectClass.ACCOUNT, ids.getValue(), new GuardedString("Password321".toCharArray()), null);
        assertNotNull(uid);

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));
        assertTrue(DN.equalsIgnoreCase(object.getName().getNameValue()));

        final Set<String> expected = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        expected.addAll(Arrays.asList(conf.getMemberships()));

        final Set<String> actual = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Object dn : object.getAttributeByName("memberOf").getValue()) {
            actual.add(dn.toString());
        }

        assertEquals(expected, actual);
    }

    @Test
    public void noRenameWithTheSameCN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, ids.getKey()),
            AttributeBuilder.buildPassword(new GuardedString("Password321".toCharArray())) });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        uid = connector.authenticate(
                ObjectClass.ACCOUNT, ids.getValue(), new GuardedString("Password321".toCharArray()), null);
        assertNotNull(uid);

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));

        assertTrue(
                util.getEntryDN(ids.getKey(), ObjectClass.ACCOUNT).equalsIgnoreCase(object.getName().getNameValue()));

        final Set<String> expected = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        expected.addAll(Arrays.asList(conf.getMemberships()));

        final Set<String> actual = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Object dn : object.getAttributeByName("memberOf").getValue()) {
            actual.add(dn.toString());
        }

        assertEquals(expected, actual);
    }

    @Test
    public void noRenameWithTheSameDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, util.getEntryDN(ids.getKey(), ObjectClass.ACCOUNT)),
            AttributeBuilder.buildPassword(new GuardedString("Password321".toCharArray())) });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        uid = connector.authenticate(
                ObjectClass.ACCOUNT, ids.getValue(), new GuardedString("Password321".toCharArray()), null);
        assertNotNull(uid);

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));

        assertTrue(
                util.getEntryDN(ids.getKey(), ObjectClass.ACCOUNT).equalsIgnoreCase(object.getName().getNameValue()));

        final Set<String> expected = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        expected.addAll(Arrays.asList(conf.getMemberships()));

        final Set<String> actual = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Object dn : object.getAttributeByName("memberOf").getValue()) {
            actual.add(dn.toString());
        }

        assertEquals(expected, actual);
    }

    @Test
    public void renameWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");

        final List<Attribute> attrToReplace =
                Arrays.asList(new Attribute[] { AttributeBuilder.build("cn", ids.getKey() + "_new") });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("cn");

        final ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // Returned attributes: cn, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("cn"));
        assertEquals(ids.getKey() + "_new", object.getAttributeByName("cn").getValue().get(0));
    }

    @Test
    public void disable() {

        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("4");

        Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.buildEnabled(false) });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(ids.getValue()),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        try {
            connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    ids.getValue(), // uid
                    new GuardedString("Password123".toCharArray()), // password
                    null);
            fail();
        } catch (ConnectorException ignore) {
            // ignore
        }

        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.buildEnabled(true) });

        uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(ids.getValue()),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                ids.getValue(), // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);
    }

    @Test
    public void issueAD22() {
        final Map.Entry<String, String> ids = util.getEntryIDs("AD22");

        assertNull("Please remove user 'uid: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), null));

        int uacValue = 0x0200;

        final Set<Attribute> attributes = util.getSimpleProfile(ids);
        attributes.add(AttributeBuilder.build(
                "userAccountControl", Collections.singletonList(String.valueOf(uacValue))));

        final OperationOptions options = new OperationOptionsBuilder().setAttributesToGet("userAccountControl").build();

        final Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, options);
        assertEquals(ids.getValue(), uid.getUidValue());

        try {
            ConnectorObject connectorObject = connector.getObject(ObjectClass.ACCOUNT, uid, options);
            assertEquals(String.valueOf(uacValue),
                    connectorObject.getAttributeByName("userAccountControl").getValue().get(0));

            uacValue = uacValue + 0x0002;
            final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
                AttributeBuilder.build("userAccountControl", String.valueOf(uacValue)) });

            connector.update(
                    ObjectClass.ACCOUNT,
                    new Uid(ids.getValue()),
                    new HashSet<Attribute>(attrToReplace),
                    options);

            connectorObject = connector.getObject(ObjectClass.ACCOUNT, uid, options);
            assertEquals(String.valueOf(uacValue),
                    connectorObject.getAttributeByName("userAccountControl").getValue().get(0));
        } finally {
            connector.delete(ObjectClass.ACCOUNT, uid, null);
            assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
        }
    }

    @Test
    public void issueAD24() {
        final ADConfiguration newconf = getSimpleConf(prop);
        newconf.setUidAttribute("uid");

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, newconf);
        final ConnectorFacade newConnector = factory.newInstance(impl);

        final Map.Entry<String, String> ids = util.getEntryIDs("AD24");

        assertNull("Please remove user 'uid: " + ids.getValue() + "' from AD",
                newConnector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids);

        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf");

        final Uid uid = newConnector.create(ObjectClass.ACCOUNT, attributes, oob.build());
        assertEquals(ids.getValue(), uid.getUidValue());

        try {
            assertNotNull(newConnector.getObject(ObjectClass.ACCOUNT, uid, oob.build()));
        } finally {
            newConnector.delete(ObjectClass.ACCOUNT, uid, null);
            assertNull(newConnector.getObject(ObjectClass.ACCOUNT, uid, null));
        }
    }

    @Test
    public void issueAD25() {
        assertNotNull(connector);
        assertNotNull(conf);

        // Ask just for cn, uid and sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("cn", "uid", "sAMAccountName");

        final Map.Entry<String, String> ids = util.getEntryIDs("6");
        ConnectorObject object = connector.getObject(ObjectClass.ACCOUNT, new Uid(ids.getValue()), oob.build());
        assertEquals(ids.getValue(), object.getUid().getUidValue());

        List<Attribute> attrToReplace =
                Arrays.asList(new Attribute[] { AttributeBuilder.build(Uid.NAME, ids.getValue() + "_new") });

        try {
            connector.update(
                    ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);
            fail();
        } catch (IllegalArgumentException ignore) {
            // ignore
        }

        attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(conf.getUidAttribute(), ids.getValue() + "_new") });

        Uid uid = connector.update(
                ObjectClass.ACCOUNT, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertEquals(ids.getValue() + "_new", uid.getUidValue());

        // restore ....
        attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(conf.getUidAttribute(), ids.getValue()) });

        uid = connector.update(ObjectClass.ACCOUNT, uid, new HashSet<Attribute>(attrToReplace), null);

        assertEquals(ids.getValue(), uid.getUidValue());
    }

    @Test
    public void issueAD27() {
        final ADConfiguration newconf = getSimpleConf(prop);
        newconf.setDefaultGroupContainer("CN=Builtin," + BASE_CONTEXT);
        newconf.setGroupBaseContexts(newconf.getDefaultGroupContainer());
        newconf.setUserBaseContexts(newconf.getDefaultPeopleContainer());

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, newconf);
        final ConnectorFacade newConnector = factory.newInstance(impl);

        final TestUtil newutil = new TestUtil(newConnector, newconf, ObjectClass.ACCOUNT, BASE_CONTEXT);

        // 1. create a new group
        Map.Entry<String, String> groupIDs =
                new AbstractMap.SimpleEntry<String, String>("GroupTestAD27", "SAAN_GroupTestAD27");

        assertNull("Please remove group 'sAMAccountName: " + groupIDs.getValue() + "' from AD",
                newConnector.getObject(ObjectClass.GROUP, new Uid(groupIDs.getValue()), null));

        Set<Attribute> attributes = newutil.getSimpleGroupProfile(groupIDs, true);

        final Attribute ldapGroups = AttributeUtil.find("ldapGroups", attributes);
        attributes.remove(ldapGroups);

        final List<String> groupsToBeAdded = new ArrayList<String>();

        if (ldapGroups != null && ldapGroups.getValue() != null) {
            groupsToBeAdded.add(
                    util.getEntryDN(util.getEntryIDs("InFilter", ObjectClass.GROUP).getKey(), ObjectClass.GROUP));
        }

        attributes.add(AttributeBuilder.build("ldapGroups", groupsToBeAdded));

        Uid groupUID = null;
        Uid userUID = null;

        try {
            groupUID = newConnector.create(ObjectClass.GROUP, attributes, null);
            assertNotNull(groupUID);

            // 2. create a new user
            Map.Entry<String, String> userIDs = newutil.getEntryIDs("AD27");

            assertNull("Please remove user 'sAMAccountName: " + userIDs.getValue() + "' from AD",
                    newConnector.getObject(ObjectClass.ACCOUNT, new Uid(userIDs.getValue()), null));

            attributes = newutil.getSimpleProfile(userIDs, false);
            userUID = newConnector.create(ObjectClass.ACCOUNT, attributes, null);
            assertNotNull(userUID);

            // 3. update user by adding membership
            List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
                AttributeBuilder.build(
                "ldapGroups",
                String.format("CN=%s,CN=Builtin,%s", groupIDs.getKey(), BASE_CONTEXT)) });

            newConnector.update(
                    ObjectClass.ACCOUNT,
                    userUID,
                    new HashSet<Attribute>(attrToReplace),
                    null);

            final OperationOptionsBuilder oob = new OperationOptionsBuilder();
            oob.setAttributesToGet("memberOf");

            final ConnectorObject object = newConnector.getObject(ObjectClass.ACCOUNT, userUID, oob.build());

            assertTrue(object.getAttributeByName("memberOf").getValue().contains(
                    String.format("CN=%s,CN=Builtin,%s", groupIDs.getKey(), BASE_CONTEXT)));
        } finally {
            if (userUID != null) {
                newConnector.delete(ObjectClass.ACCOUNT, userUID, null);
                assertNull(newConnector.getObject(ObjectClass.ACCOUNT, userUID, null));
            }
            if (groupUID != null) {
                newConnector.delete(ObjectClass.GROUP, groupUID, null);
                assertNull(newConnector.getObject(ObjectClass.GROUP, groupUID, null));
            }
        }
    }
}
