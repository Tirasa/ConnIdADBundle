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
package net.tirasa.connid.bundles.ad.schema;

import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.Uid;

public class ADSchema extends LdapSchema {
    private static final Log LOG = Log.getLog(ADSchema.class);

    public ADSchema(final ADConnection connection) {
        super(connection);
    }

    public Schema schema() {
        if (schema == null) {
            schema = new ADSchemaBuilder((ADConnection) conn).getSchema();
        }

        return schema;
    }

    @Override
    public String getLdapAttribute(ObjectClass oclass, String attrName, boolean transfer) {
        String result = null;
        if (AttributeUtil.namesEqual(Uid.NAME, attrName)) {
            result = getLdapUidAttribute(oclass);
        } else if (AttributeUtil.namesEqual(Name.NAME, attrName)) {
            result = getLdapNameAttribute(oclass);
        } else if (OperationalAttributes.PASSWORD_NAME.equals(attrName)) {
            result = getLdapPasswordAttribute(oclass);
        }

        if (result == null && !AttributeUtil.isSpecialName(attrName)) {
            result = attrName;
        }

        if (result == null && !oclass.equals(ANY_OBJECT_CLASS)) {
            LOG.warn(
                    "Attribute {0} of object class {1} is not mapped to an LDAP attribute",
                    attrName, oclass.getObjectClassValue());
        }
        return result;
    }
}
