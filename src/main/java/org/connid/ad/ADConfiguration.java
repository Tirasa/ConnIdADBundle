package org.connid.ad;

import org.identityconnectors.ldap.LdapConfiguration;

public class ADConfiguration extends LdapConfiguration {

    private String latestSyncToken;

    public ADConfiguration() {
        super();

        super.setUidAttribute("sAMAccountName");
        super.setAccountUserNameAttributes("sAMAccountName");
        super.setObjectClassesToSynchronize(new String[]{"user"});
        super.setGroupMemberAttribute("memberOf");
        super.setAccountObjectClasses(new String[]{
                    "top", "person", "organizationalPerson", "user"});
        super.setUsePagedResultControl(true);
        super.setBlockSize(Integer.MAX_VALUE);
    }

    public String getLatestSyncToken() {
        return latestSyncToken;
    }

    public void setLatestSyncToken(String latestSyncToken) {
        this.latestSyncToken = latestSyncToken;
    }
}
