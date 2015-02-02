/* 
 * Copyright 2015 ConnId.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connid.bundles.ad.crud;

import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingException;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ldap.commons.LdapModifyOperation;
import org.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;

public class ADDelete extends LdapModifyOperation {

    private final ObjectClass oclass;

    private final Uid uid;

    @SuppressWarnings("FieldNameHidesFieldInSuperclass")
    private final ADConnection conn;

    public ADDelete(
            final ADConnection conn,
            final ObjectClass oclass,
            final Uid uid) {

        super(conn);
        this.oclass = oclass;
        this.uid = uid;
        this.conn = conn;
    }

    public void delete() {
        final String entryDN = LdapSearches.getEntryDN(conn, oclass, uid);

        final Set<String> ldapGroups = new HashSet<String>(groupHelper.getLdapGroups(entryDN));

        groupHelper.removeLdapGroupMemberships(entryDN, ldapGroups);

        try {
            conn.getInitialContext().destroySubcontext(entryDN);
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }
}
