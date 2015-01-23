/* 
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2011 ConnId. All rights reserved.
 * 
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License").  You may not use this file
 * except in compliance with the License.
 * 
 * You can obtain a copy of the License at
 * http://opensource.org/licenses/cddl1.php
 * See the License for the specific language governing permissions and limitations
 * under the License.
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at http://opensource.org/licenses/cddl1.php.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package net.tirasa.connid.bundles.ad.crud;

import static org.junit.Assert.*;

import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.AbstractTest;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.Schema;
import org.junit.Test;

public class SchemaTest extends AbstractTest {

    @Test
    public void schema() {
        final Schema schema = connector.schema();
        assertNotNull(schema);

        final ObjectClassInfo info = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);

        assertNotNull(info);

        assertNotNull(info.getAttributeInfo());
        assertFalse(info.getAttributeInfo().isEmpty());
        assertNotNull(schema.getOperationOptionInfo());

        boolean sddl = false;
        boolean givenname = false;

        for (AttributeInfo attrInfo : info.getAttributeInfo()) {
            if (ADConfiguration.UCCP_FLAG.equals(attrInfo.getName())) {
                sddl = true;
                assertEquals(Boolean.class, attrInfo.getType());
            }

            if ("givenName".equalsIgnoreCase(attrInfo.getName())) {
                givenname = true;
                assertEquals(String.class, attrInfo.getType());
            }
        }

        assertTrue(sddl && givenname);
    }
}
