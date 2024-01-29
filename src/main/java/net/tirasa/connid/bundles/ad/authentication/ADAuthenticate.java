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
package net.tirasa.connid.bundles.ad.authentication;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ldap.LdapAuthenticate;
import net.tirasa.connid.bundles.ldap.LdapConnection.AuthenticationResult;
import net.tirasa.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;
import org.identityconnectors.framework.common.exceptions.PasswordExpiredException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;

public class ADAuthenticate extends LdapAuthenticate {

    private static final Log LOG = Log.getLog(ADAuthenticate.class);

    public ADAuthenticate(
            final ADConnection conn,
            final ObjectClass oclass,
            final String username,
            final OperationOptions options) {
        super(conn, oclass, username, options);
    }

    public Uid authenticate(GuardedString password) {
        final ConnectorObject authnObject = getObjectToAuthenticate();

        AuthenticationResult authnResult = null;

        if (authnObject != null) {
            final String entryDN = authnObject.getName().getNameValue();
            authnResult = conn.authenticate(entryDN, password);
        }

        if (!isSuccess(authnResult)) {
            throw new InvalidCredentialException(
                    conn.format("authenticationFailed", null, username));
        }

        try {
            authnResult.propagate();
        } catch (PasswordExpiredException e) {
            e.initUid(authnObject.getUid());
            throw e;
        }

        // AuthenticationResult did not throw an exception, 
        // so this authentication was successful.
        return authnObject.getUid();
    }

    @Override
    protected ConnectorObject getObjectToAuthenticate() {
        List<String> userNameAttrs = getUserNameAttributes();
        Map<String, ConnectorObject> entryDN2Object = new HashMap<>();
        final String dnAttributeName = conn.getConfiguration().getDnAttribute();
        for (String baseContext : ((ADConfiguration) conn.getConfiguration()).getUserBaseContexts()) {
            for (String userNameAttr : userNameAttrs) {
                Attribute attr = AttributeBuilder.build(userNameAttr, username);

                for (ConnectorObject object : LdapSearches.findObjects(conn, oclass, baseContext, attr,
                        dnAttributeName)) {
                    String entryDN = object.getAttributeByName(dnAttributeName).getValue().get(0).toString();
                    entryDN2Object.put(entryDN, object);
                }

                // If we found more than one authentication candidates, no need to continue
                if (entryDN2Object.size() > 1) {
                    throw new ConnectorSecurityException(conn.format(
                            "moreThanOneEntryMatched", null, username));
                }
            }
        }

        if (!entryDN2Object.isEmpty()) {
            return entryDN2Object.values().iterator().next();
        }

        return null;
    }

    @Override
    protected List<String> getUserNameAttributes() {
        String[] result = ADConfiguration.class.cast(conn.getConfiguration()).getUserAuthenticationAttributes();
        if (result != null && result.length > 0) {
            return Arrays.asList(result);
        }

        return super.getUserNameAttributes();
    }
}
