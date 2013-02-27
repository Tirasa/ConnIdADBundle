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
package org.connid.bundles.ad;

import java.util.ArrayList;
import java.util.List;
import org.connid.bundles.ldap.LdapConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

public class ADConfiguration extends LdapConfiguration {

    private boolean retrieveDeletedUser;

    private List<String> memberships;

    private boolean trustAllCerts;

    private boolean loading = false;

    private boolean membershipsInOr = false;

    private String defaultPeopleContainer;

    private boolean startSyncFromToday = true;

    public ADConfiguration() {
        super();

        setUidAttribute("sAMAccountName");
        setSynchronizePasswords(true);

        setSynchronizePasswords(false);
        setAccountUserNameAttributes("sAMAccountName");
        setObjectClassesToSynchronize(new String[]{"user"});
        setGroupMemberAttribute("member");
        setAccountObjectClasses(new String[]{"top", "person", "organizationalPerson", "user"});

        setUsePagedResultControl(true);
        setBlockSize(100);
        setUseBlocks(true);

        setPasswordAttribute("unicodePwd");
        setSsl(true);

        memberships = new ArrayList<String>();
        retrieveDeletedUser = true;
    }

    @ConfigurationProperty(displayMessageKey = "memberships.display",
    helpMessageKey = "memberships.help", required = true, order = 1)
    public String[] getMemberships() {
        return memberships.toArray(new String[memberships.size()]);
    }

    public void setMemberships(String... memberships) {
        this.memberships = new ArrayList<String>();

        if (memberships != null) {
            for (String membership : memberships) {
                this.memberships.add(membership.trim());
            }
        }
    }

    @ConfigurationProperty(displayMessageKey = "retrieveDeletedUser.display",
    helpMessageKey = "retrieveDeletedUser.help", order = 2)
    public boolean isRetrieveDeletedUser() {
        return retrieveDeletedUser;
    }

    public void setRetrieveDeletedUser(boolean retrieveDeletedUser) {
        this.retrieveDeletedUser = retrieveDeletedUser;
    }

    @ConfigurationProperty(displayMessageKey = "trustAllCerts.display",
    helpMessageKey = "trustAllCerts.help", order = 3)
    public boolean isTrustAllCerts() {
        return trustAllCerts;
    }

    public void setTrustAllCerts(final boolean trustAllCerts) {
        this.trustAllCerts = trustAllCerts;
    }

    @ConfigurationProperty(displayMessageKey = "loading.display",
    helpMessageKey = "loading.help", order = 4)
    public boolean isLoading() {
        return loading;
    }

    public void setLoading(boolean loading) {
        this.loading = loading;
    }

    public boolean isMembershipsInOr() {
        return membershipsInOr;
    }

    @ConfigurationProperty(displayMessageKey = "membershipsInOr.display",
    helpMessageKey = "membershipsInOr.help", order = 5)
    public void setMembershipsInOr(boolean membershipsInOr) {
        this.membershipsInOr = membershipsInOr;
    }

    @ConfigurationProperty(displayMessageKey = "defaultPeopleContainer.display",
    helpMessageKey = "defaultPeopleContainer.help", order = 6)
    public String getDefaultPeopleContainer() {
        return defaultPeopleContainer;
    }

    public void setDefaultPeopleContainer(String defaultPeopleContainer) {
        this.defaultPeopleContainer = defaultPeopleContainer;
    }

    @ConfigurationProperty(displayMessageKey = "startSyncFromToday.display",
    helpMessageKey = "startSyncFromToday.help", order = 7)
    public boolean isStartSyncFromToday() {
        return startSyncFromToday;
    }

    public void setStartSyncFromToday(boolean startSyncFromToday) {
        this.startSyncFromToday = startSyncFromToday;
    }
}
