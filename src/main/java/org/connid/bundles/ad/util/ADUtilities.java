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
package org.connid.bundles.ad.util;

import static org.connid.bundles.ad.ADConfiguration.UCCP_FLAG;
import static org.connid.bundles.ad.ADConnector.OBJECTGUID;
import static org.connid.bundles.ad.ADConnector.SDDL_ATTR;
import static org.connid.bundles.ad.ADConnector.UACCONTROL_ATTR;
import static org.connid.bundles.ad.ADConnector.UF_ACCOUNTDISABLE;
import static org.identityconnectors.common.CollectionUtil.newCaseInsensitiveSet;
import static org.identityconnectors.common.CollectionUtil.newSet;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ldap.LdapConnection;
import org.connid.bundles.ldap.commons.GroupHelper;
import org.connid.bundles.ldap.commons.LdapConstants;
import org.connid.bundles.ldap.commons.LdapEntry;
import org.connid.bundles.ldap.commons.LdapUtil;
import org.connid.bundles.ldap.schema.LdapSchemaMapping;
import org.connid.bundles.ldap.search.LdapFilter;
import org.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;

public class ADUtilities {

    private final Log LOG = Log.getLog(ADUtilities.class);

    private final ADConnection connection;

    private final GroupHelper groupHelper;

    protected static final String UCP_OBJECT_GUID = "AB721A53-1E2F-11D0-9819-00AA0040529B";

    public ADUtilities(final ADConnection connection) {
        this.connection = connection;
        groupHelper = new GroupHelper(connection);
    }

    public Set<String> getAttributesToGet(final String[] attributesToGet, final ObjectClass oclass) {
        final Set<String> result;

        if (attributesToGet != null) {
            result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(attributesToGet));
            removeNonReadableAttributes(result, oclass);
            result.add(Name.NAME);
        } else {
            // This should include Name.NAME.
            result = getAttributesReturnedByDefault(connection, oclass);
        }

        // Uid is required to build a ConnectorObject.
        result.add(Uid.NAME);

        if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
            // AD specific, for checking wether a user is enabled or not
            result.add(UACCONTROL_ATTR);
        }

        // Our password is marked as readable because of sync().
        // We really can't return it from search.
        if (result.contains(OperationalAttributes.PASSWORD_NAME)) {
            LOG.warn("Reading passwords not supported");
        }

        if (result.contains(UCCP_FLAG)) {
            result.remove(UCCP_FLAG);
            result.add(SDDL_ATTR);
        }

        return result;
    }

    private void removeNonReadableAttributes(final Set<String> attributes, final ObjectClass oclass) {
        // Since the groups attributes are fake attributes, we don't want to
        // send them to LdapSchemaMapping. This, for example, avoid an 
        // (unlikely) conflict with a custom attribute defined in the server
        // schema.
        boolean ldapGroups = attributes.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups = attributes.remove(LdapConstants.POSIX_GROUPS_NAME);

        connection.getSchemaMapping().removeNonReadableAttributes(oclass, attributes);

        if (ldapGroups) {
            attributes.add(LdapConstants.LDAP_GROUPS_NAME);
        }

        if (posixGroups) {
            attributes.add(LdapConstants.POSIX_GROUPS_NAME);
        }
    }

    public static Set<String> getAttributesReturnedByDefault(final LdapConnection conn, final ObjectClass oclass) {
        if (oclass.equals(LdapSchemaMapping.ANY_OBJECT_CLASS)) {
            return newSet(Name.NAME);
        }

        final Set<String> result = newCaseInsensitiveSet();

        final ObjectClassInfo oci = conn.getSchemaMapping().schema().findObjectClassInfo(oclass.getObjectClassValue());

        if (oci != null) {
            for (AttributeInfo info : oci.getAttributeInfo()) {
                if (info.isReturnedByDefault()) {
                    result.add(info.getName());
                }
            }
        }

        return result;
    }

    public Set<String> getLdapAttributesToGet(final Set<String> attrsToGet, final ObjectClass oclass) {
        final Set<String> cleanAttrsToGet = newCaseInsensitiveSet();
        cleanAttrsToGet.addAll(attrsToGet);
        cleanAttrsToGet.remove(LdapConstants.LDAP_GROUPS_NAME);

        boolean posixGroups = cleanAttrsToGet.remove(LdapConstants.POSIX_GROUPS_NAME);

        final Set<String> result = connection.getSchemaMapping().getLdapAttributes(oclass, cleanAttrsToGet, true);

        if (posixGroups) {
            result.add(GroupHelper.getPosixRefAttribute());
        }

        return result;
    }

    public ConnectorObject createConnectorObject(
            final String baseDN,
            final SearchResult result,
            final Collection<String> attrsToGet,
            final ObjectClass oclass)
            throws NamingException {

        return createConnectorObject(baseDN, result.getAttributes(), attrsToGet, oclass);
    }

    public ConnectorObject createConnectorObject(
            final String baseDN,
            final Attributes profile,
            final Collection<String> attrsToGet,
            final ObjectClass oclass)
            throws NamingException {

        final LdapEntry entry = LdapEntry.create(baseDN, profile);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);

        builder.setUid(connection.getSchemaMapping().createUid(oclass, entry));
        builder.setName(connection.getSchemaMapping().createName(oclass, entry));

        for (String attributeName : attrsToGet) {

            Attribute attribute = null;

            if (LdapConstants.isLdapGroups(attributeName)) {
                final Set<String> ldapGroups = new HashSet<String>(groupHelper.getLdapGroups(entry.getDN().toString()));
                attribute = AttributeBuilder.build(LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attributeName)) {
                final Set<String> posixRefAttrs = LdapUtil.getStringAttrValues(entry.getAttributes(), GroupHelper.
                        getPosixRefAttribute());
                final List<String> posixGroups = groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attributeName) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                // IMPORTANT!!! Return empty guarded string
                attribute = AttributeBuilder.build(attributeName, new GuardedString());
            } else if (UACCONTROL_ATTR.equals(attributeName) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                try {

                    final String status = profile.get(UACCONTROL_ATTR) == null || profile.get(UACCONTROL_ATTR).get()
                            == null
                                    ? null : profile.get(UACCONTROL_ATTR).get().toString();

                    if (LOG.isOk()) {
                        LOG.ok("User Account Control: {0}", status);
                    }

                    // enabled if UF_ACCOUNTDISABLE is not included (0x00002)
                    builder.addAttribute(
                            status == null || Integer.parseInt(
                                    profile.get(UACCONTROL_ATTR).get().toString())
                            % 16 != UF_ACCOUNTDISABLE
                                    ? AttributeBuilder.buildEnabled(true)
                                    : AttributeBuilder.buildEnabled(false));

                    attribute = connection.getSchemaMapping().createAttribute(oclass, attributeName, entry, false);
                } catch (NamingException e) {
                    LOG.error(e, "While fetching " + UACCONTROL_ATTR);
                }
            } else if (OBJECTGUID.equals(attributeName)) {
                attribute = AttributeBuilder.build(
                        attributeName, DirSyncUtils.getGuidAsString((byte[]) profile.get(OBJECTGUID).get()));
            } else if (SDDL_ATTR.equals(attributeName)) {
                attribute = AttributeBuilder.build(
                        UCCP_FLAG, userCannotChangePassword((byte[]) profile.get(SDDL_ATTR).get()));
            } else {
                if (profile.get(attributeName) != null) {
                    attribute = connection.getSchemaMapping().createAttribute(oclass, attributeName, entry, false);
                }
            }

            // Avoid attribute adding in case of attribute name not found
            if (attribute != null) {
                builder.addAttribute(attribute);
            }
        }

        return builder.build();
    }

    /**
     * Create a DN string starting from a set attributes and a default people container. This method has to be used if
     * __NAME__ attribute is not provided or it it is not a DN.
     *
     * @param oclass object class.
     * @param nameAttr naming attribute.
     * @param cnAttr cn attribute.
     * @return distinguished name string.
     */
    public final String getDN(final ObjectClass oclass, final Name nameAttr, final Attribute cnAttr) {

        String cn;

        if (cnAttr == null || cnAttr.getValue() == null
                || cnAttr.getValue().isEmpty()
                || cnAttr.getValue().get(0) == null
                || StringUtil.isBlank(cnAttr.getValue().get(0).toString())) {
            // Get the name attribute and consider this as the principal name.
            // Use the principal name as the CN to generate DN.
            cn = nameAttr.getNameValue();
        } else {
            // Get the common name and use this to generate the DN.
            cn = cnAttr.getValue().get(0).toString();
        }

        return "cn=" + cn + ","
                + (oclass.is(ObjectClass.ACCOUNT_NAME)
                        ? ((ADConfiguration) (connection.getConfiguration())).getDefaultPeopleContainer()
                        : ((ADConfiguration) (connection.getConfiguration())).getDefaultGroupContainer());
    }

    /**
     * Check if the String is an ldap DN.
     *
     * @param dn string to be checked.
     * @return TRUE if the value provided is a DN; FALSE otherwise.
     */
    public final boolean isDN(final String dn) {
        try {
            return StringUtil.isNotBlank(dn) && new LdapName(dn) != null;
        } catch (InvalidNameException ex) {
            return false;
        }
    }

    public String getMembershipSearchFilter(final ADConfiguration conf) {
        final StringBuilder ufilter = new StringBuilder();
        final String[] memberships = conf.getMemberships();
        if (memberships != null && memberships.length > 0) {
            ufilter.append(conf.isMembershipsInOr() ? "(|" : "(&");

            for (String group : memberships) {
                ufilter.append("(memberOf=").append(group).append(")");
            }

            ufilter.append(")");
        }
        return ufilter.toString();
    }

    public ConnectorObject getEntryToBeUpdated(final Uid uid, final ObjectClass oclass) {
        final String filter = connection.getConfiguration().getUidAttribute() + "=" + uid.getUidValue();

        final ConnectorObject obj = LdapSearches.findObject(
                connection, oclass, LdapFilter.forNativeFilter(filter), UACCONTROL_ATTR, SDDL_ATTR);

        if (obj == null) {
            throw new ConnectorException("Entry not found");
        }

        return obj;
    }

    public boolean userCannotChangePassword(final byte[] src) {
        final SDDL sddl = new SDDL(src);

        boolean res = false;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; !res && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1) {
                        if ((Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                                || (Arrays.equals(
                                        sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a }))) {
                            res = true;
                        }
                    }
                }
            }
        }

        return res;
    }

    public javax.naming.directory.Attribute userCannotChangePassword(
            final ConnectorObject obj, final Boolean cannot) {
        final Attribute ntSecurityDescriptor = obj.getAttributeByName(SDDL_ATTR);
        if (ntSecurityDescriptor == null
                || ntSecurityDescriptor.getValue() == null
                || ntSecurityDescriptor.getValue().isEmpty()) {
            return null;
        }

        final SDDL sddl = new SDDL((byte[]) ntSecurityDescriptor.getValue().get(0));

        final AceType type = cannot ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

        ACE self = null;
        ACE all = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; (all == null || self == null) && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1) {
                        if (self == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 })) {
                            self = ace;
                            self.setType(type);
                        } else if (all == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a })) {
                            all = ace;
                            all.setType(type);
                        }
                    }
                }
            }
        }

        if (self == null) {
            // prepare aces
            self = ACE.newInstance(type);
            self.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            self.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
            self.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000001));
            sid.addSubAuthority(NumberFacility.getBytes(0));
            self.setSid(sid);
            sddl.getDacl().getAces().add(self);
        }

        if (all == null) {
            all = ACE.newInstance(type);
            all.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            all.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
            all.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            final SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000005));
            sid.addSubAuthority(NumberFacility.getBytes(0x0A));
            all.setSid(sid);
            sddl.getDacl().getAces().add(all);
        }

        return new BasicAttribute(SDDL_ATTR, sddl.toByteArray());
    }
}
