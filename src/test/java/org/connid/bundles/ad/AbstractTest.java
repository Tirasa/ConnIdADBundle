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

import org.connid.bundles.ad.ADConnector;
import org.connid.bundles.ad.ADConfiguration;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Collections;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.test.common.TestHelpers;

public abstract class AbstractTest {

    /**
     * Setup logging for the {@link ADConnector}.
     */
    protected static final Log LOG = Log.getLog(ADConnector.class);

    protected static ConnectorFacade connector;

    protected static ADConfiguration conf;

    private static String USERCONTEXT;

    protected static final Properties prop = new Properties();

    public static void init(String prefix) {

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

        // Create a set of test users ...

        String cn;

        // check users existence
        for (int i = 1; i <= 10; i++) {
            cn = prefix + i;

            assertNull("Please remove user 'sAMAccountName: SAAN_" + cn + "'",
                    connector.getObject(ObjectClass.ACCOUNT, new Uid("SAAN_" + cn), null));
        }

        Set<Attribute> attributes;

        // add new users
        for (int i = 1; i <= 10; i++) {
            cn = prefix + i;

            attributes = getSimpleProfile(cn);

            final Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);

            assertNotNull(uid);
            assertEquals("SAAN_" + cn, uid.getUidValue());
        }

    }

    protected String getEntryDN(final String cn) {
        return "cn=" + cn + ",CN=Users," + USERCONTEXT;
    }

    protected static Set<Attribute> getSimpleProfile(final String cn, final boolean withDN) {
        return getSimpleProfile(cn, conf, withDN);
    }

    protected static Set<Attribute> getSimpleProfile(final String cn) {
        return getSimpleProfile(cn, conf, true);
    }

    protected static Set<Attribute> getSimpleProfile(
            final String cn, final ADConfiguration conf, final boolean withDN) {

        final Set<Attribute> attributes = new HashSet<Attribute>();

        if (withDN) {
            attributes.add(new Name("cn=" + cn + ",CN=Users," + USERCONTEXT));
        } else {
            attributes.add(new Name("SAAN_" + cn));
            attributes.add(AttributeBuilder.build("cn", Collections.singletonList(cn)));
        }

        attributes.add(AttributeBuilder.build(Uid.NAME, Collections.singletonList("SAAN_" + cn)));

        attributes.add(AttributeBuilder.buildEnabled(true));

        attributes.add(AttributeBuilder.buildPassword("Password123".toCharArray()));

        attributes.add(AttributeBuilder.build("sn", Collections.singletonList("sntest")));

        attributes.add(AttributeBuilder.build("givenName", Collections.singletonList("gntest")));

        attributes.add(AttributeBuilder.build("displayName", Collections.singletonList("dntest")));

        return attributes;
    }

    protected static ADConfiguration getSimpleConf(final Properties prop) {

        final ADConfiguration configuration = new ADConfiguration();

        configuration.setDefaultPeopleContainer("CN=Users," + USERCONTEXT);

        configuration.setObjectClassesToSynchronize("user");

        configuration.setHost(prop.getProperty("host"));
        configuration.setPort(Integer.parseInt(prop.getProperty("port")));

        configuration.setAccountObjectClasses("top", "person", "organizationalPerson", "user");

        configuration.setBaseContextsToSynchronize(prop.getProperty("baseContextToSynchronize"));

        configuration.setBaseContexts(USERCONTEXT);

        configuration.setPrincipal(prop.getProperty("principal"));

        configuration.setCredentials(new GuardedString(prop.getProperty("credentials").toCharArray()));

        configuration.setMemberships(prop.getProperty("memberships").split(";"));

        configuration.setRetrieveDeletedUser(false);

        configuration.setTrustAllCerts(true);

        configuration.setMembershipsInOr(true);

        assertFalse(configuration.getMemberships() == null || configuration.getMemberships().length == 0);

        return configuration;
    }

    public static void cleanup(final String prefix) {
        Uid uid = null;
        for (int i = 1; i <= 10; i++) {
            uid = new Uid("SAAN_" + prefix + i);

            try {
                connector.delete(ObjectClass.ACCOUNT, uid, null);
            } catch (Exception ignore) {
                // ignore exception
                LOG.error(ignore, "Error removing user {0}", uid.getUidValue());
            }

            assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
        }
    }
}
