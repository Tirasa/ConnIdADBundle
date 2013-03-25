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

import java.util.Set;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.AfterClass;
import org.junit.BeforeClass;

public class GroupTest extends AbstractTest {

    protected static TestUtil util;

    @BeforeClass
    public static void init() {
        AbstractTest.init();

        util = new TestUtil(connector, conf, ObjectClass.GROUP, GroupTest.class.getSimpleName(), BASE_CONTEXT);

        final Set<Attribute> uMemberOfAll = util.getSimpleUserProfile(util.getEntryIDs("OfAll"), conf, true);
        final Uid user = connector.create(ObjectClass.ACCOUNT, uMemberOfAll, null);
        assertNotNull(user);

        final Set<Attribute> gMemberInFilter = util.getSimpleGroupProfile(util.getEntryIDs("InFilter"), conf, true);

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

    @AfterClass
    public static void cleanup() {
        util.cleanup(10);

        Uid uid = new Uid(util.getEntryIDs("OfAll").getValue());
        connector.delete(ObjectClass.ACCOUNT, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));

        uid = new Uid(util.getEntryIDs("InFilter").getValue());
        connector.delete(ObjectClass.GROUP, uid, null);
        assertNull(connector.getObject(ObjectClass.ACCOUNT, uid, null));
    }
}
