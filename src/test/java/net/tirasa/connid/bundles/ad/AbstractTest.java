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
package net.tirasa.connid.bundles.ad;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Properties;
import java.util.Set;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.impl.api.APIConfigurationImpl;
import org.identityconnectors.framework.impl.api.local.JavaClassProperties;
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

    protected static void init() {
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
         // TODO: remove the line below when using ConnId >= 1.4.0.1
        ((APIConfigurationImpl) impl).
                setConfigurationProperties(JavaClassProperties.createConfigurationProperties(conf));

        connector = factory.newInstance(impl);

        assertNotNull(connector);
        connector.test();
    }

    protected static ADConfiguration getSimpleConf(final Properties prop) {

        final ADConfiguration configuration = new ADConfiguration();
        
        configuration.setUidAttribute("sAMAccountName");

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

    protected static void baseSetup(final TestUtil util) {
        final Set<Attribute> uMemberOfAll =
                util.getSimpleUserProfile(util.getEntryIDs("OfAll", ObjectClass.ACCOUNT), conf, true);
        final Uid user = connector.create(ObjectClass.ACCOUNT, uMemberOfAll, null);
        assertNotNull(user);

        final Set<Attribute> gMemberInFilter =
                util.getSimpleGroupProfile(util.getEntryIDs("InFilter", ObjectClass.GROUP), true);

        // remove members
        Attribute attr = AttributeUtil.find("member", gMemberInFilter);
        if (attr != null) {
            gMemberInFilter.remove(attr);
        }

        // remove memberOf
        attr = AttributeUtil.find("ldapGroups", gMemberInFilter);
        if (attr != null) {
            gMemberInFilter.remove(attr);
        }

        final Uid group = connector.create(ObjectClass.GROUP, gMemberInFilter, null);
        assertNotNull(group);

        util.createEntry(10);
    }

    public static void cleanup(final TestUtil util) {
        util.cleanup(10);

        Uid uid = new Uid(util.getEntryIDs("OfAll", ObjectClass.ACCOUNT).getValue());
        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));

        uid = new Uid(util.getEntryIDs("InFilter", ObjectClass.GROUP).getValue());
        connector.delete(ObjectClass.GROUP, uid, null);
        assertNull(connector.getObject(ObjectClass.GROUP, uid, null));
    }
}
