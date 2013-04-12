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
