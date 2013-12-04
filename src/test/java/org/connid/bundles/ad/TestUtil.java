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
package org.connid.bundles.ad;

import static org.junit.Assert.*;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;

public class TestUtil {

    /**
     * Setup logging for the {@link ADConnector}.
     */
    protected static final Log LOG = Log.getLog(TestUtil.class);

    private final ObjectClass oclass;

    private final ConnectorFacade connector;

    private final ADConfiguration conf;

    public TestUtil(
            final ConnectorFacade connector,
            final ADConfiguration conf,
            final ObjectClass oclass,
            final String basecontext) {
        this.oclass = oclass;
        this.connector = connector;
        this.conf = conf;
    }

    /**
     * Create a set of test etries.
     */
    public void createEntry(final int num) {
        // check entries existence
        for (int i = 1; i <= num; i++) {
            final Map.Entry<String, String> ids = getEntryIDs(String.valueOf(i));

            assertNull("Please remove etry 'sAMAccountName: " + ids.getValue() + "'",
                    connector.getObject(oclass, new Uid(ids.getValue()), null));
        }

        Set<Attribute> attributes;

        // add new users
        for (int i = 1; i <= num; i++) {
            final Map.Entry<String, String> ids = getEntryIDs(String.valueOf(i));

            attributes = getSimpleProfile(ids);

            final Uid uid = connector.create(oclass, attributes, null);

            assertNotNull(uid);
            assertEquals(ids.getValue(), uid.getUidValue());
        }

    }

    public String getEntryDN(final String cn, final ObjectClass oclass) {
        return String.format("cn=%s,%s", cn, oclass.equals(ObjectClass.ACCOUNT)
                ? conf.getDefaultPeopleContainer() : conf.getDefaultGroupContainer());
    }

    public Set<Attribute> getSimpleProfile(final Map.Entry<String, String> ids, final boolean withDN) {
        if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
            return getSimpleUserProfile(ids, conf, withDN);
        } else {
            return getSimpleGroupProfile(ids, withDN);
        }
    }

    public Set<Attribute> getSimpleProfile(final Map.Entry<String, String> ids) {
        if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
            return getSimpleUserProfile(ids, conf, true);
        } else {
            return getSimpleGroupProfile(ids, true);
        }
    }

    public Set<Attribute> getSimpleUserProfile(
            final Map.Entry<String, String> ids, final ADConfiguration conf, final boolean withDN) {

        final Set<Attribute> attributes = new HashSet<Attribute>();

        if (withDN) {
            attributes.add(new Name(getEntryDN(ids.getKey(), ObjectClass.ACCOUNT)));
        } else {
            attributes.add(new Name(ids.getValue()));
            attributes.add(AttributeBuilder.build("cn", Collections.singletonList(ids.getKey())));
        }

        attributes.add(AttributeBuilder.build(Uid.NAME, Collections.singletonList(ids.getValue())));

        attributes.add(AttributeBuilder.buildEnabled(true));

        if (conf.isSsl()) {
            attributes.add(AttributeBuilder.buildPassword("Password123".toCharArray()));
        }

        attributes.add(AttributeBuilder.build("sn", Collections.singletonList("sntest")));

        attributes.add(AttributeBuilder.build("givenName", Collections.singletonList("gntest")));

        attributes.add(AttributeBuilder.build("displayName", Collections.singletonList("dntest")));

        return attributes;
    }

    public Set<Attribute> getSimpleGroupProfile(final Map.Entry<String, String> ids, final boolean withDN) {

        final Set<Attribute> attributes = new HashSet<Attribute>();

        if (withDN) {
            attributes.add(new Name(getEntryDN(ids.getKey(), ObjectClass.GROUP)));
        } else {
            attributes.add(new Name(ids.getValue()));
            attributes.add(AttributeBuilder.build("cn", Collections.singletonList(ids.getKey())));
        }

        attributes.add(AttributeBuilder.build(Uid.NAME, Collections.singletonList(ids.getValue())));

        attributes.add(AttributeBuilder.build("member", Collections.singletonList(
                getEntryDN(getEntryIDs("OfAll", ObjectClass.ACCOUNT).getKey(), ObjectClass.ACCOUNT))));

        attributes.add(AttributeBuilder.build("ldapGroups", Collections.singletonList(
                getEntryDN(getEntryIDs("InFilter", ObjectClass.GROUP).getKey(), ObjectClass.GROUP))));

        return attributes;
    }

    public void cleanup(final int num) {
        Uid uid = null;
        for (int i = 1; i <= num; i++) {
            uid = new Uid(getEntryIDs(String.valueOf(i)).getValue());

            try {
                connector.delete(oclass, uid, null);
            } catch (Exception ignore) {
                // ignore exception
                LOG.error(ignore, "Error removing user {0}", uid.getUidValue());
            }

            assertNull(connector.getObject(oclass, uid, null));
        }
    }

    public Map.Entry<String, String> getEntryIDs(final String suffix, final ObjectClass oclass) {
        final String prefix = oclass.equals(ObjectClass.ACCOUNT) ? "UserTest" : "GroupTest";
        return new AbstractMap.SimpleEntry<String, String>(prefix + suffix, "SAAN_" + prefix + suffix);
    }

    public Map.Entry<String, String> getEntryIDs(final String suffix) {
        return getEntryIDs(suffix, oclass);
    }
}
