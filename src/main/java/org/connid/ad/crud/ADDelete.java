/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.     
 * 
 * The contents of this file are subject to the terms of the Common Development 
 * and Distribution License("CDDL") (the "License").  You may not use this file 
 * except in compliance with the License.
 * 
 * You can obtain a copy of the License at 
 * http://IdentityConnectors.dev.java.net/legal/license.txt
 * See the License for the specific language governing permissions and limitations 
 * under the License. 
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields 
 * enclosed by brackets [] replaced by your own identifying information: 
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.connid.ad.crud;

import java.util.List;
import java.util.Set;

import javax.naming.NamingException;

import org.connid.ad.ADConnection;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.ldap.LdapModifyOperation;
import org.identityconnectors.ldap.GroupHelper.GroupMembership;
import org.identityconnectors.ldap.search.LdapSearches;

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

        if (conn.getConfiguration().isMaintainLdapGroupMembership()) {
            final List<String> ldapGroups = groupHelper.getLdapGroups(entryDN);
            groupHelper.removeLdapGroupMemberships(entryDN, ldapGroups);
        }

        if (conn.getConfiguration().isMaintainPosixGroupMembership()) {
            final PosixGroupMember posixMember = new PosixGroupMember(entryDN);
            final Set<GroupMembership> memberships =
                    posixMember.getPosixGroupMemberships();
            groupHelper.removePosixGroupMemberships(memberships);
        }

        try {
            conn.getInitialContext().destroySubcontext(entryDN);
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }
}
