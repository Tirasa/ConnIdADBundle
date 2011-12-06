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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.connid.ad.AbstractTest;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;

import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class CrudTest extends AbstractTest {

    @BeforeClass
    public static void init() {
        init(CrudTest.class.getSimpleName());
    }

    @Test
    public void schema() {
        final Schema schema = connector.schema();
        assertNotNull(schema);

        final ObjectClassInfo info =
                schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);

        assertNotNull(info);

        assertNotNull(info.getAttributeInfo());
        assertFalse(info.getAttributeInfo().isEmpty());
        assertNotNull(schema.getOperationOptionInfo());
    }

    @Test
    public void search() {

        String SAAN = "SAAN_" + CrudTest.class.getSimpleName() + "1";

        // create filter
        final Filter filter = FilterBuilder.equalTo(
                AttributeBuilder.build("sAMAccountName", SAAN));

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

        assertFalse(results.isEmpty());
        assertEquals(1, results.size());
        assertEquals(Collections.singletonList(SAAN), results.get(0).getValue());

        connector.schema();
    }

    @Test
    public void read() {
        String SAAN = "SAAN_" + CrudTest.class.getSimpleName() + "2";

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("sAMAccountName"));

        final ConnectorObject object = connector.getObject(
                ObjectClass.ACCOUNT, new Uid(SAAN), oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: sAMAccountName, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("sAMAccountName"));
        assertEquals(
                Collections.singletonList(SAAN),
                object.getAttributeByName("sAMAccountName").getValue());
    }

    @Test
    public void create() {
        assertNotNull(connector);
        assertNotNull(conf);

        final String CN = CrudTest.class.getSimpleName() + "11";
        final String SAAN = "SAAN_" + CN;

        assertNull("Please remove user 'sAMAccountName: " + SAAN + "' from AD",
                connector.getObject(ObjectClass.ACCOUNT, new Uid(SAAN), null));

        final Set<Attribute> attributes = getSimpleProfile(CN);

        final Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);
        assertNotNull(uid);
        assertEquals(SAAN, uid.getUidValue());

        // Ask just for memberOf
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("memberOf"));

        // retrieve created object
        final ConnectorObject object =
                connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        // check for memberOf attribute
        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: memberOf, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("memberOf"));
        assertEquals(// check on Set to ignore order
                new HashSet(Arrays.asList(conf.getMemberships())),
                new HashSet(object.getAttributeByName("memberOf").getValue()));

        assertEquals(SAAN, object.getUid().getUidValue());

        assertEquals(getEntryDN(CN).toLowerCase(),
                object.getName().getNameValue().toLowerCase());

        final Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                SAAN, // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
    }

    @Test
    public void update() {
        assertNotNull(connector);
        assertNotNull(conf);

        final String SAAN = "SAAN_" + CrudTest.class.getSimpleName() + "3";

        Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                SAAN, // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        Throwable t = null;
        try {
            authUid = connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    SAAN, // uid
                    new GuardedString("Password321".toCharArray()), // password
                    null);
        } catch (ConnectorException e) {
            t = e;
        }

        assertNotNull(t);

        final List<Attribute> attrToReplace = Arrays.asList(new Attribute[]{
                    AttributeBuilder.build("givenName", "gnupdate"),
                    AttributeBuilder.buildPassword(
                    new GuardedString("Password321".toCharArray()))});

        Uid uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(SAAN),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(SAAN, uid.getUidValue());

        // Ask just for sAMAccountName
        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet(Collections.singleton("givenName"));

        final ConnectorObject object =
                connector.getObject(ObjectClass.ACCOUNT, uid, oob.build());

        assertNotNull(object);
        assertNotNull(object.getAttributes());
        // Returned attributes: givenName, NAME and UID
        assertEquals(3, object.getAttributes().size());
        assertNotNull(object.getAttributeByName("givenName"));
        assertEquals(
                Collections.singletonList("gnupdate"),
                object.getAttributeByName("givenName").getValue());

        t = null;

        try {
            authUid = connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    SAAN, // uid
                    new GuardedString("Password123".toCharArray()), // password
                    null);
        } catch (ConnectorException e) {
            t = e;
        }

        assertNotNull(t);

        authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                SAAN, // uid
                new GuardedString("Password321".toCharArray()), // password
                null);

        assertNotNull(authUid);
    }

    @Test
    public void disable() {

        assertNotNull(connector);
        assertNotNull(conf);

        final String SAAN = "SAAN_" + CrudTest.class.getSimpleName() + "4";

        Uid authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                SAAN, // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);

        List<Attribute> attrToReplace = Arrays.asList(
                new Attribute[]{AttributeBuilder.buildEnabled(false)});

        Uid uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(SAAN),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(SAAN, uid.getUidValue());

        Throwable t = null;
        try {
            authUid = connector.authenticate(
                    ObjectClass.ACCOUNT, // object class
                    SAAN, // uid
                    new GuardedString("Password123".toCharArray()), // password
                    null);
        } catch (ConnectorException e) {
            t = e;
        }

        assertNotNull(t);

        attrToReplace = Arrays.asList(
                new Attribute[]{AttributeBuilder.buildEnabled(true)});

        uid = connector.update(
                ObjectClass.ACCOUNT,
                new Uid(SAAN),
                new HashSet<Attribute>(attrToReplace),
                null);

        assertNotNull(uid);
        assertEquals(SAAN, uid.getUidValue());

        authUid = connector.authenticate(
                ObjectClass.ACCOUNT, // object class
                SAAN, // uid
                new GuardedString("Password123".toCharArray()), // password
                null);

        assertNotNull(authUid);
    }

    @AfterClass
    public static void cleanup() {
        cleanup(CrudTest.class.getSimpleName());
    }
}
