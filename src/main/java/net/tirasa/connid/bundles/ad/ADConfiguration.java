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
package net.tirasa.connid.bundles.ad;

import java.util.ArrayList;
import java.util.List;
import net.tirasa.connid.bundles.ad.search.ADDefaultSearchStrategy;
import net.tirasa.connid.bundles.ad.sync.ADSyncStrategy;
import net.tirasa.connid.bundles.ad.util.ADUtilities;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.search.DefaultSearchStrategy;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.ConfigurationProperty;

public final class ADConfiguration extends LdapConfiguration {

    private final Log LOG = Log.getLog(ADConfiguration.class);

    private boolean retrieveDeletedUser = true;

    private boolean retrieveDeletedGroup = true;

    private boolean retrieveDeletedAnyObject = true;

    public static final String PROMPT_USER_FLAG = "pwdLastSet";

    public static final String PROMPT_USER_VALUE = "0";

    public static final String NOT_PROMPT_USER_VALUE = "-1";

    public static final String LOCK_OUT_FLAG = "lockoutTime";

    public static final String LOCK_OUT_DEFAULT_VALUE = "0";

    public static final String UCCP_FLAG = "userCannotChangePassword";

    public static final String PNE_FLAG = "passwordNeverExpires";

    public static final String CN_NAME = "CN";

    public static final String PRIMARY_GROUP_DN_NAME = "primaryGroupDN";

    private List<String> memberships;

    private boolean membershipConservativePolicy;

    private boolean trustAllCerts;

    private boolean membershipsInOr = false;

    private String defaultPeopleContainer;

    private String defaultGroupContainer;

    private String defaultAnyObjectContainer;

    private String[] groupBaseContexts = {};
    
    private String[] userBaseContexts = {};
    
    private String[] anyObjectBaseContexts = {};

    private String groupOwnerReferenceAttribute = "managedBy";

    private boolean pwdUpdateOnly = false;

    private boolean excludeAttributeChangesOnUpdate = false;

    private String defaultIdAttribute = "cn";

    private String[] userAuthenticationAttributes = {};

    public ADConfiguration() {
        super();

        
        setAccountObjectClasses("top", "person", "organizationalPerson", "user");
        setAccountUserNameAttributes("sAMAccountName");
        setUidAttribute("sAMAccountName");

        setGroupObjectClasses("top", "group");
        setGroupNameAttributes("sAMAccountName");
        setGidAttribute("sAMAccountName");

        setAnyObjectClasses("top");
        setAnyObjectNameAttributes("cn");
        setAoidAttribute("cn");
        setDefaultIdAttribute("cn");
        setSynchronizePasswords(false);

        setObjectClassesToSynchronize(new String[] { "user" });
        setGroupMemberAttribute("member");

        setPasswordAttribute("unicodePwd");
        setPort(636);
        setSsl(true);

        setSyncStrategy("net.tirasa.connid.bundles.ad.sync.ADSyncStrategy");
        setFallbackSyncStrategyClass(ADSyncStrategy.class);
        setConnectionClass(ADConnection.class);

        memberships = new ArrayList<>();
    }

    @Override
    public DefaultSearchStrategy newDefaultSearchStrategy(boolean ignoreNonExistingBaseDN) {
        return new ADDefaultSearchStrategy(ignoreNonExistingBaseDN);
    }

    @ConfigurationProperty(displayMessageKey = "memberships.display",
            helpMessageKey = "memberships.help", order = 1)
    public String[] getMemberships() {
        return memberships.toArray(new String[0]);
    }

    public void setMemberships(final String... memberships) {
        this.memberships = new ArrayList<>();

        if (memberships != null) {
            for (String membership : memberships) {
                if (ADUtilities.isDN(membership)) {
                    this.memberships.add(membership.trim());
                } else {
                    LOG.warn("Skip membership! \"{0}\" is not a valid distinguished name (DN)", membership);
                }
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

    @ConfigurationProperty(displayMessageKey = "retrieveDeletedGroup.display",
            helpMessageKey = "retrieveDeletedGroup.help", order = 3)
    public boolean isRetrieveDeletedGroup() {
        return this.retrieveDeletedGroup;
    }

    public void setRetrieveDeletedGroup(boolean retrieveDeletedGroup) {
        this.retrieveDeletedGroup = retrieveDeletedGroup;
    }

    @ConfigurationProperty(displayMessageKey = "retrieveDeletedAnyObject.display",
    helpMessageKey = "retrieveDeletedAnyObject.help", order = 4)
    public boolean isRetrieveDeletedAnyObject() {
        return this.retrieveDeletedAnyObject;
    }

    public void setRetrieveDeletedAnyObject(boolean retrieveDeletedAnyObject) {
        this.retrieveDeletedAnyObject = retrieveDeletedAnyObject;
    }


    @ConfigurationProperty(displayMessageKey = "trustAllCerts.display",
            helpMessageKey = "trustAllCerts.help", order = 5)
    public boolean isTrustAllCerts() {
        return trustAllCerts;
    }

    public void setTrustAllCerts(final boolean trustAllCerts) {
        this.trustAllCerts = trustAllCerts;
    }

    public boolean isMembershipsInOr() {
        return membershipsInOr;
    }

    @ConfigurationProperty(displayMessageKey = "membershipsInOr.display",
            helpMessageKey = "membershipsInOr.help", order = 6)
    public void setMembershipsInOr(boolean membershipsInOr) {
        this.membershipsInOr = membershipsInOr;
    }

    @ConfigurationProperty(displayMessageKey = "defaultPeopleContainer.display",
            helpMessageKey = "defaultPeopleContainer.help", order = 7)
    public String getDefaultPeopleContainer() {
        if (StringUtil.isBlank(defaultPeopleContainer)) {
            return getBaseContexts() == null || getBaseContexts().length < 1
                    ? null : getBaseContexts()[0];
        } else {
            return defaultPeopleContainer;
        }
    }

    public void setDefaultPeopleContainer(String defaultPeopleContainer) {
        this.defaultPeopleContainer = defaultPeopleContainer;
    }

    @ConfigurationProperty(displayMessageKey = "defaultGroupContainer.display",
            helpMessageKey = "defaultGroupContainer.help", order = 8)
    public String getDefaultGroupContainer() {
        if (StringUtil.isBlank(defaultGroupContainer)) {
            return getBaseContexts() == null || getBaseContexts().length < 1
                    ? null : getBaseContexts()[0];
        } else {
            return defaultGroupContainer;
        }
    }

    public void setDefaultGroupContainer(String defaultGroupContainer) {
        this.defaultGroupContainer = defaultGroupContainer;
    }

    @ConfigurationProperty(displayMessageKey = "defaultAnyObjectContainer.display",
            helpMessageKey = "defaultAnyObjectContainer.help", order = 9)
    public String getDefaultAnyObjectContainer() {
        if (StringUtil.isBlank(defaultAnyObjectContainer)) {
            return getBaseContexts() == null || getBaseContexts().length < 1
                    ? null : getBaseContexts()[0];
        } else {
            return defaultAnyObjectContainer;
        }
    }

    public void setDefaultAnyObjectContainer(String defaultAnyObjectContainer) {
        this.defaultAnyObjectContainer = defaultAnyObjectContainer;
    }

    @ConfigurationProperty(displayMessageKey = "groupBaseContexts.display",
            helpMessageKey = "groupBaseContexts.help", order = 10)
    public String[] getGroupBaseContexts() {
        if (groupBaseContexts != null && groupBaseContexts.length > 0) {
            // return specified configuration
            return groupBaseContexts.clone();
        } else {
            // return root suffixes
            return getBaseContexts();
        }
    }

    public void setGroupBaseContexts(String... baseContexts) {
        this.groupBaseContexts = baseContexts.clone();
        // update base context everytime ...
        super.setBaseContexts(this.getBaseContexts());
    }

    @ConfigurationProperty(displayMessageKey = "userBaseContexts.display",
            helpMessageKey = "userBaseContexts.help", order = 11)
    public String[] getUserBaseContexts() {
        if (userBaseContexts != null && userBaseContexts.length > 0) {
            // return specified configuration
            return userBaseContexts.clone();
        } else {
            // return root suffixes
            return getBaseContexts();
        }
    }

    public void setUserBaseContexts(final String... baseContexts) {
        this.userBaseContexts = baseContexts.clone();
        // update base context everytime ...
        super.setBaseContexts(this.getBaseContexts());
    }

    @ConfigurationProperty(displayMessageKey = "anyObjectBaseContexts.display",
            helpMessageKey = "anyObjectBaseContexts.help", order = 12)
    public String[] getAnyObjectBaseContexts() {
        if (anyObjectBaseContexts != null && anyObjectBaseContexts.length > 0) {
            // return specified configuration
            return anyObjectBaseContexts.clone();
        } else {
            // return root suffixes
            return getBaseContexts();
        }
    }

    public void setAnyObjectBaseContexts(final String... baseContexts) {
        this.anyObjectBaseContexts = baseContexts.clone();
        // update base context everytime ...
        super.setBaseContexts(this.getBaseContexts());
    }

    @ConfigurationProperty(displayMessageKey = "groupOwnerReferenceAttribute.display",
            helpMessageKey = "groupOwnerReferenceAttribute.help", order = 13)
    public String getGroupOwnerReferenceAttribute() {
        return StringUtil.isBlank(groupOwnerReferenceAttribute) ? "managedBy" : groupOwnerReferenceAttribute;
    }

    public void setGroupOwnerReferenceAttribute(String groupOwnerReferenceAttribute) {
        this.groupOwnerReferenceAttribute = groupOwnerReferenceAttribute;
    }

    public boolean isPwdUpdateOnly() {
        return pwdUpdateOnly;
    }

    @ConfigurationProperty(displayMessageKey = "pwdUpdateOnly.display",
            helpMessageKey = "pwdUpdateOnly.help", required = true, order = 14)
    public void setPwdUpdateOnly(boolean pwdUpdateOnly) {
        this.pwdUpdateOnly = pwdUpdateOnly;
    }

    @ConfigurationProperty(displayMessageKey = "membershipConservativePolicy.display",
            helpMessageKey = "membershipConservativePolicy.help", order = 15)
    public boolean isMembershipConservativePolicy() {
        return membershipConservativePolicy;
    }

    public void setMembershipConservativePolicy(boolean membershipConservativePolicy) {
        this.membershipConservativePolicy = membershipConservativePolicy;
    }

    @ConfigurationProperty(order = 16,
            displayMessageKey = "defaultIdAttribute.display",
            helpMessageKey = "defaultIdAttribute.help")
    public String getDefaultIdAttribute() {
        return defaultIdAttribute;
    }

    public void setDefaultIdAttribute(final String defaultIdAttribute) {
        this.defaultIdAttribute = defaultIdAttribute;
    }

    @ConfigurationProperty(displayMessageKey = "excludeAttributeChangesOnUpdate.display",
            helpMessageKey = "excludeAttributeChangesOnUpdate.help", order = 17)
    public boolean isExcludeAttributeChangesOnUpdate() {
        return excludeAttributeChangesOnUpdate;
    }

    public void setExcludeAttributeChangesOnUpdate(boolean excludeAttributeChangesOnUpdate) {
        this.excludeAttributeChangesOnUpdate = excludeAttributeChangesOnUpdate;
    }

    @ConfigurationProperty(displayMessageKey = "userAuthenticationAttributes.display",
            helpMessageKey = "userAuthenticationAttributes.help", order = 18)
    public String[] getUserAuthenticationAttributes() {
        if (userAuthenticationAttributes != null && userAuthenticationAttributes.length > 0) {
            return userAuthenticationAttributes.clone();
        } else {
            return new String[0];
        }
    }

    public void setUserAuthenticationAttributes(final String... userAuthenticationAttributes) {
        if (userAuthenticationAttributes == null || userAuthenticationAttributes.length == 0) {
            this.userAuthenticationAttributes = new String[0];
        } else {
            this.userAuthenticationAttributes = userAuthenticationAttributes.clone();
        }
    }
}
