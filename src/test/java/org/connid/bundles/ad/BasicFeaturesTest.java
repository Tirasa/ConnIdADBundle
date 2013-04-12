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

import org.connid.bundles.ad.util.DirSyncUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;

import org.junit.BeforeClass;
import org.junit.Test;

public class BasicFeaturesTest {

    /**
     * Setup logging for the {@link DatabaseTableConnector}.
     */
    private static final Log LOG = Log.getLog(BasicFeaturesTest.class);

    private static ADConnector connector;

    @BeforeClass
    public static void init() {

        final ADConfiguration conf = new ADConfiguration();
        conf.setObjectClassesToSynchronize("user");
        conf.setAccountSearchFilter("");
        conf.setHost("localhost");
        conf.setPort(389);
        conf.setChangeLogBlockSize(100);
        conf.setAccountObjectClasses(
                "top", "person", "organizationalPerson", "user");
        conf.setBaseContextsToSynchronize("o=isp");
        conf.setSynchronizePasswords(false);
        conf.setPasswordAttribute("userPassword");
        conf.setChangeNumberAttribute("fake");
        conf.setPrincipal("cn=Administrator,cn=Users,o=isp");
        conf.setCredentials(new GuardedString("password".toCharArray()));
        conf.setUserBaseContexts("cn=users,o=isp");
        conf.setReadSchema(false);

        conf.setMemberships(
                "cn=groupA,cn=group,o=isp",
                "cn=groupB,cn=group,o=isp",
                "cn=groupC,cn=group,o=isp");

        connector = new ADConnector();
        connector.init(conf);
    }

    @Test
    public void checkConfiguration() {
        assertNotNull(connector);
        assertNotNull(connector.getConfiguration());
        connector.getConfiguration().validate();
    }

    @Test
    public void createLdapFilter() {
        assertNotNull(connector);
        assertNotNull(connector.getConfiguration());

        final String filter = DirSyncUtils.createLdapUFilter((ADConfiguration) connector.getConfiguration());

        assertNotNull(filter);
        assertFalse(filter.isEmpty());

        assertEquals(
                "(|(&(objectClass=user)"
                + "(&(memberOf=cn=groupA,cn=group,o=isp)"
                + "(memberOf=cn=groupB,cn=group,o=isp)"
                + "(memberOf=cn=groupC,cn=group,o=isp)))"
                + "(&(objectClass=group)"
                + "(|(distinguishedName=cn=groupA,cn=group,o=isp)"
                + "(distinguishedName=cn=groupB,cn=group,o=isp)"
                + "(distinguishedName=cn=groupC,cn=group,o=isp)))"
                + "(&(isDeleted=TRUE)(objectClass=user)))", filter);
    }

    @Test
    public void createDirSyncFilter() {
        assertNotNull(connector);
        assertNotNull(connector.getConfiguration());

        final String filter = DirSyncUtils.createDirSyncUFilter((ADConfiguration) connector.getConfiguration());

        assertNotNull(filter);
        assertFalse(filter.isEmpty());

        assertEquals(
                "(|(&(objectClass=user)"
                + "(&(memberOf=cn=groupA,cn=group,o=isp)"
                + "(memberOf=cn=groupB,cn=group,o=isp)"
                + "(memberOf=cn=groupC,cn=group,o=isp)))"
                + "(objectClass=group)"
                + "(&(isDeleted=TRUE)(objectClass=user)))", filter);
    }
}
