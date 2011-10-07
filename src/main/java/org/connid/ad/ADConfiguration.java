/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2011 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License. You can obtain
 * a copy of the License at https://glassfish.dev.java.net/public/CDDL+GPL.html
 * or glassfish/bootstrap/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/bootstrap/legal/LICENSE.txt.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.  If applicable, add the following below the License
 * Header, with the fields enclosed by brackets [] replaced by your own
 * identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 */
package org.connid.ad;

import java.util.ArrayList;
import java.util.List;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.ldap.LdapConfiguration;

public class ADConfiguration extends LdapConfiguration {

    private String latestSyncToken;

    private boolean retrieveDeletedUser;

    private List<String> memberships;

    public ADConfiguration() {
        super();

        super.setUidAttribute("sAMAccountName");
        super.setAccountUserNameAttributes("sAMAccountName");
        super.setObjectClassesToSynchronize(new String[]{"user"});
        super.setGroupMemberAttribute("member");
        super.setAccountObjectClasses(new String[]{
                    "top", "person", "organizationalPerson", "user"});
        super.setUsePagedResultControl(true);
        super.setBlockSize(Integer.MAX_VALUE);

        memberships = new ArrayList<String>();
        retrieveDeletedUser = true;
    }

    public String getLatestSyncToken() {
        return latestSyncToken;
    }

    public void setLatestSyncToken(String latestSyncToken) {
        this.latestSyncToken = latestSyncToken;
    }

    @ConfigurationProperty(displayMessageKey = "memberships.display",
    helpMessageKey = "memberships.help", required = true, order = 1)
    public String[] getMemberships() {
        return memberships.toArray(new String[memberships.size()]);
    }

    public void setMemberships(String... memberships) {
        this.memberships = new ArrayList<String>();

        for (String membership : memberships) {
            this.memberships.add(membership.trim());
        }
    }

    @ConfigurationProperty(displayMessageKey = "retrieveDeletedUser.display",
    helpMessageKey = "retrieveDeletedUser.help", required = true, order = 2)
    public boolean isRetrieveDeletedUser() {
        return retrieveDeletedUser;
    }

    public void setRetrieveDeletedUser(boolean retrieveDeletedUser) {
        this.retrieveDeletedUser = retrieveDeletedUser;
    }
}
