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

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ldap.search.LdapInternalSearch;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;

public class DirSyncUtils {

    public static String createDirSyncFilter(final ADConfiguration conf) {

        final String[] memberships = conf.getMemberships();

        final String isDeleted =
                String.valueOf(conf.isRetrieveDeletedUser()).toUpperCase();

        final StringBuilder filter = new StringBuilder();
        final StringBuilder mfilter = new StringBuilder();
        final StringBuilder ufilter = new StringBuilder();

        mfilter.append("(objectClass=group)");

        if (memberships != null && memberships.length > 0) {
            ufilter.append(conf.isMembershipsInOr() ? "(|" : "(&");

            for (String group : memberships) {
                ufilter.append("(memberOf=").append(group).append(")");
            }

            ufilter.append(")");
        }

        ufilter.insert(0, "(&(objectClass=user)").append(")");

        filter.append("(|").append(ufilter).append(mfilter).
                append("(&(isDeleted=").
                append(isDeleted).
                append(")(objectClass=user)))");

        return filter.toString();
    }

    public static String createLdapFilter(final ADConfiguration conf) {

        final String[] memberships = conf.getMemberships();

        final String isDeleted =
                String.valueOf(conf.isRetrieveDeletedUser()).toUpperCase();

        final StringBuilder filter = new StringBuilder();
        final StringBuilder mfilter = new StringBuilder();
        final StringBuilder ufilter = new StringBuilder();

        if (memberships != null && memberships.length > 0) {
            mfilter.append("(&(objectClass=group)(|");
            ufilter.append(conf.isMembershipsInOr() ? "(|" : "(&");

            for (String group : memberships) {
                mfilter.append("(distinguishedName=").append(group).append(")");
                ufilter.append("(memberOf=").append(group).append(")");
            }

            ufilter.append(")");
            mfilter.append("))");
        }

        ufilter.insert(0, "(&(objectClass=user)").append(")");

        filter.append("(|").append(ufilter).append(mfilter).
                append("(&(isDeleted=").
                append(isDeleted).
                append(")(objectClass=user)))");

        return filter.toString();
    }

    private static String AddLeadingZero(int k) {
        return (k <= 0xF)
                ? "0" + Integer.toHexString(k) : Integer.toHexString(k);
    }

    public static String getGuidAsString(byte[] GUID) {
        String strGUID = "";
        String byteGUID = "";

        for (int c = 0; c < GUID.length; c++) {
            byteGUID = byteGUID + "\\" + AddLeadingZero((int) GUID[c] & 0xFF);
        }

        //convert the GUID into string format
        strGUID = strGUID + AddLeadingZero((int) GUID[3] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[2] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[1] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[0] & 0xFF);
        strGUID = strGUID + "-";
        strGUID = strGUID + AddLeadingZero((int) GUID[5] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[4] & 0xFF);
        strGUID = strGUID + "-";
        strGUID = strGUID + AddLeadingZero((int) GUID[7] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[6] & 0xFF);
        strGUID = strGUID + "-";
        strGUID = strGUID + AddLeadingZero((int) GUID[8] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[9] & 0xFF);
        strGUID = strGUID + "-";
        strGUID = strGUID + AddLeadingZero((int) GUID[10] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[11] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[12] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[13] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[14] & 0xFF);
        strGUID = strGUID + AddLeadingZero((int) GUID[15] & 0xFF);

        return strGUID;
    }

    /**
     * Verify custom filter (used to validate any retrieved user).
     *
     * @param ctx ldap context.
     * @param dn user distinguished name.
     * @param conf connector configuration.
     * @return TRUE if verified; FALSE otherwise.
     */
    public static boolean verifyCustomFilter(
            final LdapContext ctx,
            final String dn,
            final ADConfiguration conf) {

        final String filter = getFilter(conf);

        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE);
        searchCtls.setReturningAttributes(new String[]{});

        boolean found = true;

        if (StringUtil.isNotBlank(filter)) {
            try {
                final NamingEnumeration res =
                        ctx.search(dn, filter, searchCtls);

                found = res != null && res.hasMoreElements();
            } catch (NamingException ex) {
                found = false;
            }
        }

        return found;
    }

    /**
     * Verify complete filter including the custom one. This method is used to validate users 'IN' group.
     *
     * @param ctx ldap context.
     * @param dn user distinguished name.
     * @param conf connector configuration.
     * @return TRUE if verified; FALSE otherwise.
     */
    public static boolean verifyFilter(
            final LdapContext ctx,
            final String dn,
            final ADConfiguration conf) {

        final StringBuilder filter = new StringBuilder();
        filter.append("(&(").append(createLdapFilter(conf)).append(")");

        filter.append(getFilter(conf) != null ? getFilter(conf) : "").append(")");

        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE);
        searchCtls.setReturningAttributes(new String[]{});

        boolean found = true;

        if (StringUtil.isNotBlank(filter.toString())) {
            try {

                final NamingEnumeration res = ctx.search(dn, filter.toString(), searchCtls);
                found = res != null && res.hasMoreElements();

            } catch (NamingException ex) {
                found = false;
            }
        }

        return found;
    }

    private static String getFilter(final AbstractConfiguration conf) {
        return ((ADConfiguration) conf).getAccountSearchFilter();
    }
}
