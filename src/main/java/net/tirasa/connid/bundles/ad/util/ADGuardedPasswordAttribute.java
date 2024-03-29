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
package net.tirasa.connid.bundles.ad.util;

import java.nio.charset.Charset;

import java.util.List;
import javax.naming.directory.BasicAttribute;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

import net.tirasa.connid.bundles.ldap.schema.GuardedPasswordAttribute;

public abstract class ADGuardedPasswordAttribute extends GuardedPasswordAttribute {

    private static final Log LOG = Log.getLog(ADGuardedPasswordAttribute.class);

    public static ADGuardedPasswordAttribute create(
            final String attrName, final Attribute attr) {

        assert attr.is(OperationalAttributes.PASSWORD_NAME);

        final List<Object> value = attr.getValue();

        if (value != null && !value.isEmpty()) {
            return ADGuardedPasswordAttribute.create(attrName,
                    (GuardedString) value.get(0));
        } else {
            return ADGuardedPasswordAttribute.create(attrName);
        }
    }

    public static ADGuardedPasswordAttribute create(
            final String attrName, final GuardedString password) {
        return new Simple(attrName, password);
    }

    public static ADGuardedPasswordAttribute create(final String attrName) {
        return new Empty(attrName);
    }

    private static final class Simple extends ADGuardedPasswordAttribute {

        private final String attrName;

        private final GuardedString password;

        private Simple(String attrName, GuardedString password) {
            this.attrName = attrName;
            this.password = password;
        }

        public void access(final Accessor accessor) {
            password.access(clearChars -> {
                final String quotedPwd = "\"" + new String(clearChars) + "\"";

                byte[] unicodePwd = quotedPwd.getBytes(Charset.forName("UTF-16LE"));
                final BasicAttribute attr = new BasicAttribute(attrName, unicodePwd);
                accessor.access(attr);
            });
        }
    }

    private static final class Empty extends ADGuardedPasswordAttribute {

        private final String attrName;

        private Empty(String attrName) {
            this.attrName = attrName;
        }

        public void access(Accessor accessor) {
            accessor.access(new BasicAttribute(attrName));
        }
    }
}
