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
import org.connid.bundles.ad.GroupTest;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.Test;

public class GroupCrudTest extends GroupTest {

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

        connector.search(ObjectClass.GROUP, filter, handler, oob.build());

        assertEquals(1, results.size());
        assertEquals(Collections.singletonList(ids.getValue()), results.get(0).getValue());
    }

    @Test
    public void searchByDefaultCustomFilter() {

        Map.Entry<String, String> ids = util.getEntryIDs("1");

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

        connector.search(ObjectClass.GROUP, null, handler, oob.build());

        assertEquals(10, results.size());

        ids = new AbstractMap.SimpleEntry<String, String>("grptmp", "grptmp");
        final Uid uid = connector.create(ObjectClass.GROUP, util.getSimpleProfile(ids), null);
        assertNotNull(uid);

        results.clear();
        connector.search(ObjectClass.GROUP, null, handler, oob.build());

        // retrieve 10 then 11
        assertEquals(10, results.size());

        connector.delete(ObjectClass.GROUP, uid, null);
    }

    @Test
    public void read() {
        final Map.Entry<String, String> ids = util.getEntryIDs("2");

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("sAMAccountName"));

        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, new Uid(ids.getValue()), oob.build());

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

        assertNull("Please remove group 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.GROUP, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids);

        final Uid uid = connector.create(ObjectClass.GROUP, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("member"));

        // retrieve created object
        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // check for memberOf attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: NAME and UID
        assertEquals(3, object.getAttributes().size());

        assertEquals(ids.getValue(), object.getUid().getUidValue());

        assertEquals(
                util.getEntryDN(ids.getKey(), ObjectClass.GROUP).toLowerCase(),
                object.getName().getNameValue().toLowerCase());

        connector.delete(ObjectClass.GROUP, uid, null);
        assertNull(connector.getObject(ObjectClass.GROUP, uid, null));
    }

    @Test
    public void createWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("nodn11");

        assertNull("Please remove group 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.GROUP, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids, false);

        final Uid uid = connector.create(ObjectClass.GROUP, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("member"));

        // retrieve created object
        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // check for memberOf attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertFalse(object.getAttributeByName("member").getValue().isEmpty());

        assertEquals(ids.getValue(), object.getUid().getUidValue());

        assertEquals(
                util.getEntryDN(ids.getKey(), ObjectClass.GROUP).toLowerCase(),
                object.getName().getNameValue().toLowerCase());

        connector.delete(ObjectClass.GROUP, uid, null);
        assertNull(connector.getObject(ObjectClass.GROUP, uid, null));
    }

    @Test
    public void checkLdapGroups() {
        assertNotNull(connector);
        assertNotNull(conf);

        String baseContext = prop.getProperty("baseContext");

        final Map.Entry<String, String> ids = util.getEntryIDs("20");

        assertNull("Please remove user 'sAMAccountName: " + ids.getValue() + "' from AD",
                connector.getObject(ObjectClass.GROUP, new Uid(ids.getValue()), null));

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

        Uid uid = connector.create(ObjectClass.GROUP, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf", "ldapGroups");

        // retrieve created object
        ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

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

        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("ldapGroups",
            "CN=Schema Admins,CN=Users," + baseContext,
            "CN=GroupTestInFilter,CN=Users," + baseContext) });

        uid = connector.update(
                ObjectClass.GROUP,
                uid,
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("ldapGroups",
            "CN=Schema Admins,CN=Users," + baseContext,
            "CN=Cert Publishers,CN=Users," + baseContext,
            "CN=GroupTestInFilter,CN=Users," + baseContext) });

        uid = connector.update(
                ObjectClass.GROUP,
                uid,
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        connector.delete(ObjectClass.GROUP, uid, null);
        assertNull(connector.getObject(ObjectClass.GROUP, uid, null));
    }

    @Test
    public void update() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("3");

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("description"));

        ConnectorObject object = connector.getObject(ObjectClass.GROUP, new Uid(ids.getValue()), oob.build());
        assertNotNull(object);

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build("description", "a new description") });

        Uid uid = connector.update(
                ObjectClass.GROUP,
                new Uid(ids.getValue()),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: description, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("description"));
        assertEquals(
                Collections.singletonList("a new description"), object.getAttributeByName("description").getValue());
    }

    @Test
    public void rename() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");

        final String DN = util.getEntryDN(ids.getKey() + "-new", ObjectClass.GROUP);

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build(Name.NAME, DN) });

        Uid uid = connector.update(
                ObjectClass.GROUP, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("member"));

        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // Returned attributes: NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertFalse(object.getAttributeByName("member").getValue().isEmpty());
        assertTrue(DN.equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void noRenameWithTheSameCN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, ids.getKey()) });

        Uid uid = connector.update(
                ObjectClass.GROUP, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("member"));

        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertFalse(object.getAttributeByName("member").getValue().isEmpty());

        assertTrue(util.getEntryDN(ids.getKey(), ObjectClass.GROUP).equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void noRenameWithTheSameDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, util.getEntryDN(ids.getKey(), ObjectClass.GROUP)) });

        Uid uid = connector.update(
                ObjectClass.GROUP, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("member"));

        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // Returned attributes: NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertFalse(object.getAttributeByName("member").getValue().isEmpty());

        assertTrue(util.getEntryDN(ids.getKey(), ObjectClass.GROUP).equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void renameWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");

        final List<Attribute> attrToReplace =
                Arrays.asList(new Attribute[] { AttributeBuilder.build("cn", ids.getKey() + "_new") });

        Uid uid = connector.update(
                ObjectClass.GROUP, new Uid(ids.getValue()), new HashSet<Attribute>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("cn");

        final ConnectorObject object = connector.getObject(ObjectClass.GROUP, uid, oob.build());

        // Returned attributes: cn, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("cn"));
        assertEquals(ids.getKey() + "_new", object.getAttributeByName("cn").getValue().get(0));
    }
}
