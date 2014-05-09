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
package org.connid.ad.crud;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;
import org.connid.ad.ADConfiguration;
import org.connid.ad.ADConnection;
import org.connid.ad.ADConnector;
import org.connid.ad.AbstractTest;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.BeforeClass;
import org.junit.Test;

public class Issue28Test extends AbstractTest {

    private final int ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x0008;

    private final int ADS_GROUP_TYPE_SECURITY_ENABLED = 0x80000000;

    @BeforeClass
    public static void init() {
        try {
            prop.load(AbstractTest.class.getResourceAsStream("/ad.properties"));
        } catch (IOException e) {
            LOG.error(e, "Error loading properties file");
        }

        USERCONTEXT = prop.getProperty("usersBaseContext");

        conf = getSimpleConf(prop);

        assertNotNull(conf);
        conf.validate();

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, conf);

        connector = factory.newInstance(impl);

        assertNotNull(connector);
        connector.test();
    }

    @Test
    public void updateUserWithoutLdapGroups() throws NamingException {
        // Let's create the following structure

        // --- OU = __TEMP__
        //    |--- CN = __GROUP__
        //    |--- OU = __TEMP1__
        //        | --- CN = __GROUP1__
        //    |--- OU = __TEMP2__
        //        | --- CN = __GROUP1__
        // Then, working with __TEMP__ as a base context (for both users and groups), create a new user member of a 
        // groups in a different tree (maybe at the same level of __TEMP__) and groups in __TEMP__ tree.
        // Update the user without specifying ldapGroups attribute and check for mermberships.
        final String baseContext = prop.getProperty("usersBaseContext");
        final String tmpctx = "ou=__TEMP__, " + baseContext;

        final ADConfiguration tempconf = getSimpleConf(prop);
        tempconf.setSsl(true);
        tempconf.setBaseContexts(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setMemberships();
        assertNotNull(tempconf);
        tempconf.validate();

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, tempconf);
        final ConnectorFacade tempconnector = factory.newInstance(impl);
        assertNotNull(tempconnector);
        tempconnector.test();

        final ADConnection connection = new ADConnection(tempconf);
        final LdapContext ctx = connection.getInitialContext();

        final Attributes attrs = new BasicAttributes(true);
        BasicAttribute objclass = new BasicAttribute("objectclass");
        objclass.add("top");
        objclass.add("organizationalUnit");
        attrs.put(objclass);

        final String outemp1 = "ou=__TEMP1__, " + tmpctx;
        final String outemp2 = "ou=__TEMP2__, " + tmpctx;

        DirContext basectx = ctx.createSubcontext(tmpctx, attrs); // returns if fail to be sure to work in a new OUx

        try {
            createSampleGroup("__GROUP__", basectx);

            DirContext subctx = ctx.createSubcontext(outemp1, attrs);
            createSampleGroup("__GROUP1__", subctx);

            subctx = ctx.createSubcontext(outemp2, attrs);
            createSampleGroup("__GROUP2__", subctx);

            final String CN = Issue28Test.class.getSimpleName() + "20";
            final String SAAN = "SAAN_" + CN;

            assertNull("Please remove user 'sAMAccountName: " + SAAN + "' from AD",
                    tempconnector.getObject(ObjectClass.ACCOUNT, new Uid(SAAN), null));

            final Set<Attribute> attributes = getSimpleProfile(CN, false);

            attributes.add(AttributeBuilder.build("ldapGroups",
                    "CN=__GROUP__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP1__,OU=__TEMP1__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP2__,OU=__TEMP2__,OU=__TEMP__," + baseContext,
                    "CN=Cert Publishers,CN=Users," + baseContext,
                    "CN=Schema Admins,CN=Users," + baseContext));

            Uid uid = tempconnector.create(ObjectClass.ACCOUNT, attributes, null);
            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            // Ask just for memberOf
            final OperationOptionsBuilder oob = new OperationOptionsBuilder();
            oob.setAttributesToGet("memberOf", "ldapGroups");

            // retrieve created object
            ConnectorObject object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            // check for memberOf attribute
            assertNotNull(object);
            assertNotNull(object.getAttributes());

            // Returned attributes: memberOf, NAME and UID
            assertEquals(4, object.getAttributes().size());
            assertNotNull(object.getAttributeByName("memberOf"));

            assertEquals(5, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(3, object.getAttributeByName("ldapGroups").getValue().size());

            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));

            final List<Attribute> attrToReplace = Arrays.asList(new Attribute[]{AttributeBuilder.build("givenName",
                "newgn")});

            uid = tempconnector.update(
                    ObjectClass.ACCOUNT,
                    new Uid(SAAN),
                    new HashSet<Attribute>(attrToReplace),
                    null);

            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            assertEquals(5, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(3, object.getAttributeByName("ldapGroups").getValue().size());

            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));
        } finally {
            removeTreeQuitely(basectx);
        }
    }

    @Test
    public void updateUserWithLdapGroups() throws NamingException {
        // Let's create the following structure

        // --- OU = __TEMP__
        //    |--- CN = __GROUP__
        //    |--- OU = __TEMP1__
        //        | --- CN = __GROUP1__
        //    |--- OU = __TEMP2__
        //        | --- CN = __GROUP1__
        // Then, working with __TEMP__ as a base context (for both users and groups), create a new user member of a 
        // groups in a different tree (maybe at the same level of __TEMP__) and groups in __TEMP__ tree.
        // Update the user without specifying ldapGroups attribute and check for mermberships.
        final String baseContext = prop.getProperty("usersBaseContext");
        final String tmpctx = "ou=__TEMP__, " + baseContext;

        final ADConfiguration tempconf = getSimpleConf(prop);
        tempconf.setSsl(true);
        tempconf.setBaseContexts(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setMemberships();
        assertNotNull(tempconf);
        tempconf.validate();

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, tempconf);
        final ConnectorFacade tempconnector = factory.newInstance(impl);
        assertNotNull(tempconnector);
        tempconnector.test();

        final ADConnection connection = new ADConnection(tempconf);
        final LdapContext ctx = connection.getInitialContext();

        final Attributes attrs = new BasicAttributes(true);
        BasicAttribute objclass = new BasicAttribute("objectclass");
        objclass.add("top");
        objclass.add("organizationalUnit");
        attrs.put(objclass);

        final String outemp1 = "ou=__TEMP1__, " + tmpctx;
        final String outemp2 = "ou=__TEMP2__, " + tmpctx;

        DirContext basectx = ctx.createSubcontext(tmpctx, attrs); // returns if fail to be sure to work in a new OUx

        try {
            createSampleGroup("__GROUP__", basectx);

            DirContext subctx = ctx.createSubcontext(outemp1, attrs);
            createSampleGroup("__GROUP1__", subctx);

            subctx = ctx.createSubcontext(outemp2, attrs);
            createSampleGroup("__GROUP2__", subctx);

            final String CN = Issue28Test.class.getSimpleName() + "20";
            final String SAAN = "SAAN_" + CN;

            assertNull("Please remove user 'sAMAccountName: " + SAAN + "' from AD",
                    tempconnector.getObject(ObjectClass.ACCOUNT, new Uid(SAAN), null));

            final Set<Attribute> attributes = getSimpleProfile(CN, false);

            attributes.add(AttributeBuilder.build("ldapGroups",
                    "CN=__GROUP__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP1__,OU=__TEMP1__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP2__,OU=__TEMP2__,OU=__TEMP__," + baseContext,
                    "CN=Cert Publishers,CN=Users," + baseContext,
                    "CN=Schema Admins,CN=Users," + baseContext));

            Uid uid = tempconnector.create(ObjectClass.ACCOUNT, attributes, null);
            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            // Ask just for memberOf
            final OperationOptionsBuilder oob = new OperationOptionsBuilder();
            oob.setAttributesToGet("memberOf", "ldapGroups");

            // retrieve created object
            ConnectorObject object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            // check for memberOf attribute
            assertNotNull(object);
            assertNotNull(object.getAttributes());

            // Returned attributes: memberOf, NAME and UID
            assertEquals(4, object.getAttributes().size());
            assertNotNull(object.getAttributeByName("memberOf"));

            assertEquals(5, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(3, object.getAttributeByName("ldapGroups").getValue().size());

            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));

            final List<Attribute> attrToReplace = new ArrayList<Attribute>();
            attrToReplace.addAll(Arrays.asList(new Attribute[]{AttributeBuilder.build("givenName", "newgn")}));
            attrToReplace.add(AttributeBuilder.build("ldapGroups",
                    "CN=__GROUP__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP1__,OU=__TEMP1__,OU=__TEMP__," + baseContext));

            uid = tempconnector.update(
                    ObjectClass.ACCOUNT,
                    new Uid(SAAN),
                    new HashSet<Attribute>(attrToReplace),
                    null);

            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            assertEquals(4, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(2, object.getAttributeByName("ldapGroups").getValue().size());

            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));
        } finally {
            removeTreeQuitely(basectx);
        }
    }
    
    @Test
    public void updateUserWithEmptyLdapGroups() throws NamingException {
        // Let's create the following structure

        // --- OU = __TEMP__
        //    |--- CN = __GROUP__
        //    |--- OU = __TEMP1__
        //        | --- CN = __GROUP1__
        //    |--- OU = __TEMP2__
        //        | --- CN = __GROUP1__
        // Then, working with __TEMP__ as a base context (for both users and groups), create a new user member of a 
        // groups in a different tree (maybe at the same level of __TEMP__) and groups in __TEMP__ tree.
        // Update the user without specifying ldapGroups attribute and check for mermberships.
        final String baseContext = prop.getProperty("usersBaseContext");
        final String tmpctx = "ou=__TEMP__, " + baseContext;

        final ADConfiguration tempconf = getSimpleConf(prop);
        tempconf.setSsl(true);
        tempconf.setBaseContexts(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setDefaultPeopleContainer(tmpctx);
        tempconf.setMemberships();
        assertNotNull(tempconf);
        tempconf.validate();

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, tempconf);
        final ConnectorFacade tempconnector = factory.newInstance(impl);
        assertNotNull(tempconnector);
        tempconnector.test();

        final ADConnection connection = new ADConnection(tempconf);
        final LdapContext ctx = connection.getInitialContext();

        final Attributes attrs = new BasicAttributes(true);
        BasicAttribute objclass = new BasicAttribute("objectclass");
        objclass.add("top");
        objclass.add("organizationalUnit");
        attrs.put(objclass);

        final String outemp1 = "ou=__TEMP1__, " + tmpctx;
        final String outemp2 = "ou=__TEMP2__, " + tmpctx;

        DirContext basectx = ctx.createSubcontext(tmpctx, attrs); // returns if fail to be sure to work in a new OUx

        try {
            createSampleGroup("__GROUP__", basectx);

            DirContext subctx = ctx.createSubcontext(outemp1, attrs);
            createSampleGroup("__GROUP1__", subctx);

            subctx = ctx.createSubcontext(outemp2, attrs);
            createSampleGroup("__GROUP2__", subctx);

            final String CN = Issue28Test.class.getSimpleName() + "20";
            final String SAAN = "SAAN_" + CN;

            assertNull("Please remove user 'sAMAccountName: " + SAAN + "' from AD",
                    tempconnector.getObject(ObjectClass.ACCOUNT, new Uid(SAAN), null));

            final Set<Attribute> attributes = getSimpleProfile(CN, false);

            attributes.add(AttributeBuilder.build("ldapGroups",
                    "CN=__GROUP__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP1__,OU=__TEMP1__,OU=__TEMP__," + baseContext,
                    "CN=__GROUP2__,OU=__TEMP2__,OU=__TEMP__," + baseContext,
                    "CN=Cert Publishers,CN=Users," + baseContext,
                    "CN=Schema Admins,CN=Users," + baseContext));

            Uid uid = tempconnector.create(ObjectClass.ACCOUNT, attributes, null);
            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            // Ask just for memberOf
            final OperationOptionsBuilder oob = new OperationOptionsBuilder();
            oob.setAttributesToGet("memberOf", "ldapGroups");

            // retrieve created object
            ConnectorObject object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            // check for memberOf attribute
            assertNotNull(object);
            assertNotNull(object.getAttributes());

            // Returned attributes: memberOf, NAME and UID
            assertEquals(4, object.getAttributes().size());
            assertNotNull(object.getAttributeByName("memberOf"));

            assertEquals(5, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(3, object.getAttributeByName("ldapGroups").getValue().size());

            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertTrue(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));

            final List<Attribute> attrToReplace = new ArrayList<Attribute>();
            attrToReplace.addAll(Arrays.asList(new Attribute[]{AttributeBuilder.build("givenName", "newgn")}));
            attrToReplace.add(AttributeBuilder.build("ldapGroups", new ArrayList<Object>()));

            uid = tempconnector.update(
                    ObjectClass.ACCOUNT,
                    new Uid(SAAN),
                    new HashSet<Attribute>(attrToReplace),
                    null);

            assertNotNull(uid);
            assertEquals(SAAN, uid.getUidValue());

            object = tempconnector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

            assertEquals(2, object.getAttributeByName("memberOf").getValue().size());
            assertEquals(0, object.getAttributeByName("ldapGroups").getValue().size());

            assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP__,ou=__TEMP__," + baseContext));
            assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP1__,OU=__TEMP1__,ou=__TEMP__," + baseContext));
            assertFalse(object.getAttributeByName("ldapGroups").getValue().contains(
                    "CN=__GROUP2__,OU=__TEMP2__,ou=__TEMP__," + baseContext));
        } finally {
            removeTreeQuitely(basectx);
        }
    }

    private void createSampleGroup(final String name, final DirContext ctx) throws NamingException {
        final Attributes attrs = new BasicAttributes(true);
        attrs.put(new BasicAttribute("objectclass", "group"));
        attrs.put(new BasicAttribute("cn", name));
        attrs.put(new BasicAttribute("sAMAccountName", name));
        attrs.put("groupType", Integer.toString(ADS_GROUP_TYPE_UNIVERSAL_GROUP + ADS_GROUP_TYPE_SECURITY_ENABLED));

        ctx.createSubcontext("cn=" + name, attrs);
    }

    private void removeTreeQuitely(final DirContext context) {
        // remove descendants ...
        removeQuitely("", context);

        // remove itself ...
        try {
            context.destroySubcontext("");
        } catch (NamingException ignore) {
            if (LOG.isOk()) {
                LOG.ok(ignore, "Failure removing test tree");
            }
        }
    }

    private void removeQuitely(final String subcontext, final DirContext context) {
        try {
            final NamingEnumeration<NameClassPair> list = context.list(subcontext);

            // Go through each item in list
            while (list.hasMore()) {
                final String toBeRemoved = list.next().getName() + (StringUtil.isBlank(subcontext) ? "" : ","
                        + subcontext);

                removeQuitely(toBeRemoved, context);
                context.destroySubcontext(toBeRemoved);
            }
        } catch (Exception ignore) {
            if (LOG.isOk()) {
                LOG.ok(ignore, "Failure removing test tree");
            }
        }
    }
}
