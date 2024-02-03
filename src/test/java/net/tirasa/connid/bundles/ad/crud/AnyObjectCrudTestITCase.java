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
package net.tirasa.connid.bundles.ad.crud;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnector;
import net.tirasa.connid.bundles.ad.AnyObjectTest;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;

import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SortKey;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.framework.impl.api.APIConfigurationImpl;
import org.identityconnectors.framework.impl.api.local.JavaClassProperties;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.Test;

public class AnyObjectCrudTestITCase extends AnyObjectTest {

    @Test
    public void pagedSearch() {
        final List<ConnectorObject> results = new ArrayList<>();
        final ResultsHandler handler = results::add;

        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(conf.getAoidAttribute());
        oob.setPageSize(2);
        oob.setSortKeys(new SortKey(conf.getAoidAttribute(), false));

        connector.search(LdapSchema.ANY_OBJECT_CLASS, null, handler, oob.build());

        assertEquals(2, results.size());

        results.clear();

        String cookie = "";
        do {
            oob.setPagedResultsCookie(cookie);
            final SearchResult searchResult = connector.search(LdapSchema.ANY_OBJECT_CLASS, null, handler, oob.build());
            cookie = searchResult.getPagedResultsCookie();
        } while (cookie != null);

        assertEquals(11, results.size());
    }

    @Test
    public void search() {

        final Map.Entry<String, String> ids = util.getEntryIDs("1");

        // create filter
        final Filter filter = FilterBuilder.equalTo(AttributeBuilder.build(conf.getAoidAttribute(), ids.getValue()));

        // create results handler
        final List<ConnectorObject> results = new ArrayList<>();
        final ResultsHandler handler = results::add;

        // create options for returning attributes
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(conf.getAoidAttribute());

        connector.search(LdapSchema.ANY_OBJECT_CLASS, filter, handler, oob.build());

        assertEquals(1, results.size());
        assertEquals(Collections.singletonList(ids.getValue()),
                results.get(0).getAttributeByName(conf.getAoidAttribute()).getValue());
    }

    @Test
    public void read() {
        final Map.Entry<String, String> ids = util.getEntryIDs("2");

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(conf.getAoidAttribute());

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: sAMAccountName, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName(conf.getAoidAttribute()));
        assertEquals(Collections.singletonList(ids.getValue()), object.getAttributeByName(conf.getAoidAttribute()).getValue());
    }

    @Test
    public void create() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("11");

        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids);

        final Uid uid = connector.create(LdapSchema.ANY_OBJECT_CLASS, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for serialNumber and description
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Arrays.asList("serialNumber", "description"));

        // retrieve created object
        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // check for serialNumber & description attributes
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: serialNumber, description, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("serialNumber"));
        assertNotNull(object.getAttributeByName("description"));

        assertEquals(ids.getValue(), object.getUid().getUidValue());
        assertEquals(
                util.getEntryDN(ids.getKey(), LdapSchema.ANY_OBJECT_CLASS).toLowerCase(),
                object.getName().getNameValue().toLowerCase());


        connector.delete(LdapSchema.ANY_OBJECT_CLASS, uid, null);
        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, null));
    }

    @Test
    public void createWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("nodn11");

        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids, false);

        final Uid uid = connector.create(LdapSchema.ANY_OBJECT_CLASS, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("serialNumber");

        // retrieve created object
        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // check for serialNumber attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());

        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("serialNumber"));

        assertEquals(ids.getValue(), object.getUid().getUidValue());
        assertEquals(util.getEntryDN(ids.getKey(),
                LdapSchema.ANY_OBJECT_CLASS).toLowerCase(), object.getName().getNameValue().toLowerCase());

        connector.delete(LdapSchema.ANY_OBJECT_CLASS, uid, null);
        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, null));
    }

    @Test
    public void checkLdapGroups() {
        assertNotNull(connector);
        assertNotNull(conf);

        String baseContext = PROP.getProperty("baseContext");

        final Map.Entry<String, String> ids = util.getEntryIDs("20");

        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), null));

        final Set<Attribute> attributes = util.getSimpleProfile(ids, false);

        final Attribute ldapGroups = AttributeUtil.find("ldapGroups", attributes);
        attributes.remove(ldapGroups);

        final List<String> groupsToBeAdded = new ArrayList<>();

        if (ldapGroups != null && ldapGroups.getValue() != null) {
            for (Object obj : ldapGroups.getValue()) {
                groupsToBeAdded.add(obj.toString());
            }
        }

        groupsToBeAdded.add("CN=Cert Publishers,CN=Users," + baseContext);
        groupsToBeAdded.add("CN=Schema Admins,CN=Users," + baseContext);

        attributes.add(AttributeBuilder.build("ldapGroups", groupsToBeAdded));

        Uid uid = connector.create(LdapSchema.ANY_OBJECT_CLASS, attributes, null);
        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("memberOf", "ldapGroups");

        // retrieve created object
        ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

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
                LdapSchema.ANY_OBJECT_CLASS,
                uid,
                new HashSet<>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("ldapGroups",
            "CN=Schema Admins,CN=Users," + baseContext,
            "CN=Cert Publishers,CN=Users," + baseContext) });

        uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS,
                uid,
                new HashSet<>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Cert Publishers,CN=Users," + baseContext));
        assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                "CN=Schema Admins,CN=Users," + baseContext));

        connector.delete(LdapSchema.ANY_OBJECT_CLASS, uid, null);
        assertNull(connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, null));
    }

    @Test
    public void update() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("3");

        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build("description", "descriptionupdate"),
            AttributeBuilder.build("serialNumber", "serialnumberupdate")});

        Uid uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS,
                new Uid(ids.getValue()),
                new HashSet<>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("description", "serialNumber");

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: description, serialNumber, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("description"));
        assertEquals(
                Collections.singletonList("descriptionupdate"),
                object.getAttributeByName("description").getValue());
        assertNotNull(object.getAttributeByName("serialNumber"));
        assertEquals(
                Collections.singletonList("serialnumberupdate"),
                object.getAttributeByName("serialNumber").getValue());
    }

    @Test
    public void rename() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");

        final String DN = "cn=renamed_" + ids.getKey() + ",cn=Computers," + BASE_CONTEXT;

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, DN)});

        Uid uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), new HashSet<>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());


        // Ask just for description and serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("description", "serialNumber");

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // Returned attributes: description, serialNumber, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("description"));
        assertNotNull(object.getAttributeByName("serialNumber"));
        assertTrue(DN.equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void noRenameWithTheSameCN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, ids.getKey())});

        Uid uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), new HashSet<>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for description and serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("description", "serialNumber");

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // Returned attributes: description, serialNumber, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("description"));
        assertNotNull(object.getAttributeByName("serialNumber"));

        assertTrue(
                util.getEntryDN(ids.getKey(), LdapSchema.ANY_OBJECT_CLASS).equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void noRenameWithTheSameDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("6");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build(Name.NAME, util.getEntryDN(ids.getKey(), LdapSchema.ANY_OBJECT_CLASS)) });

        Uid uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), new HashSet<>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for description and serialNumber
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("description", "serialNumber");

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // Returned attributes: description, serialNumber, NAME and UID
        assertEquals(4, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("description"));
        assertNotNull(object.getAttributeByName("serialNumber"));

        assertTrue(
                util.getEntryDN(ids.getKey(), LdapSchema.ANY_OBJECT_CLASS).equalsIgnoreCase(object.getName().getNameValue()));
    }

    @Test
    public void renameWithoutDN() {
        assertNotNull(connector);
        assertNotNull(conf);

        final Map.Entry<String, String> ids = util.getEntryIDs("5");

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("cn", ids.getKey()
            + "_new") });

        Uid uid = connector.update(
                LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), new HashSet<>(attrToReplace), null);

        assertNotNull(uid);
        assertEquals(ids.getValue(), uid.getUidValue());

        // Ask just for cn
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("cn");

        final ConnectorObject object = connector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        // Returned attributes: cn, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("cn"));
        assertEquals(ids.getKey() + "_new", object.getAttributeByName("cn").getValue().get(0));
    }

    @Test
    public void excludeAttributeChangesOnUpdate() {
        final ADConfiguration newconf = getSimpleConf(PROP);
        newconf.setExcludeAttributeChangesOnUpdate(true);

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, newconf);
        // TODO: remove the line below when using ConnId >= 1.4.0.1
        ((APIConfigurationImpl) impl).
                setConfigurationProperties(JavaClassProperties.createConfigurationProperties(newconf));

        final ConnectorFacade newConnector = factory.newInstance(impl);

        final Map.Entry<String, String> ids = util.getEntryIDs("9");

        // 2. Update without pwd ....
        List<Attribute> attrToReplace = Arrays.asList(new Attribute[] {
            AttributeBuilder.build("serialNumber", "excludeAttributeChangesOnUpdate") });

        Uid uid = newConnector.update(
                LdapSchema.ANY_OBJECT_CLASS,
                new Uid(ids.getValue()),
                new HashSet<>(attrToReplace),
                null);
        assertEquals(ids.getValue(), uid.getUidValue());

        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("serialNumber");

        ConnectorObject object = newConnector.getObject(LdapSchema.ANY_OBJECT_CLASS, uid, oob.build());

        List<Object> serialNumber = object.getAttributeByName("serialNumber").getValue();
        assertTrue(serialNumber.size() == 1 && !serialNumber.contains("excludeAttributeChangesOnUpdate"));

        attrToReplace = Arrays.asList(new Attribute[] { AttributeBuilder.build("cn", ids.getKey() + "_new") });

        // 0. rename should be denied
        try {
            newConnector.update(
                    LdapSchema.ANY_OBJECT_CLASS, new Uid(ids.getValue()), new HashSet<>(attrToReplace), null);
            fail();
        } catch (Exception e) {
            // ignore
        }
    }
}