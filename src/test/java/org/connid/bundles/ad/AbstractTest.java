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

import java.io.IOException;
import java.util.Properties;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.test.common.TestHelpers;

public abstract class AbstractTest {

    /**
     * Setup logging for the {@link ADConnector}.
     */
    protected static final Log LOG = Log.getLog(ADConnector.class);

    protected static ConnectorFacade connector;

    protected static ADConfiguration conf;

    protected static final Properties prop = new Properties();

    protected static String BASE_CONTEXT;

    public static void init() {
        try {
            prop.load(AbstractTest.class.getResourceAsStream("/ad.properties"));
        } catch (IOException e) {
            LOG.error(e, "Error loading properties file");
        }

        BASE_CONTEXT = prop.getProperty("baseContext");

        conf = getSimpleConf(prop);

        assertNotNull(conf);
        conf.validate();

        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        final APIConfiguration impl = TestHelpers.createTestConfiguration(ADConnector.class, conf);

        connector = factory.newInstance(impl);

        assertNotNull(connector);
        connector.test();
    }

    protected static ADConfiguration getSimpleConf(final Properties prop) {

        final ADConfiguration configuration = new ADConfiguration();

        configuration.setDefaultPeopleContainer("CN=Users," + BASE_CONTEXT);
        configuration.setDefaultGroupContainer("CN=Users," + BASE_CONTEXT);

        configuration.setObjectClassesToSynchronize("user");

        configuration.setHost(prop.getProperty("host"));
        configuration.setPort(Integer.parseInt(prop.getProperty("port")));

        configuration.setAccountObjectClasses("top", "person", "organizationalPerson", "user");

        configuration.setBaseContextsToSynchronize(prop.getProperty("baseContextToSynchronize"));

        configuration.setUserBaseContexts(BASE_CONTEXT);

        // set default group container as Fgroup search context
        configuration.setGroupBaseContexts(configuration.getDefaultGroupContainer());

        configuration.setPrincipal(prop.getProperty("principal"));

        configuration.setCredentials(new GuardedString(prop.getProperty("credentials").toCharArray()));

        configuration.setMemberships(prop.getProperty("memberships").split(";"));

        configuration.setRetrieveDeletedUser(false);

        configuration.setTrustAllCerts(true);

        configuration.setMembershipsInOr(true);

        configuration.setUserSearchScope("subtree");
        configuration.setGroupSearchScope("subtree");

        configuration.setGroupSearchFilter(
                "(&(cn=GroupTest*)(memberOf=CN=GroupTestInFilter,CN=Users," + BASE_CONTEXT + "))");

        assertFalse(configuration.getMemberships() == null || configuration.getMemberships().length == 0);

        return configuration;
    }
}
