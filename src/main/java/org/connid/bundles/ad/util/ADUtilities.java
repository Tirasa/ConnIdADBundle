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

import static org.connid.bundles.ad.ADConnector.UACCONTROL_ATTR;
import static org.connid.bundles.ad.ADConnector.UF_ACCOUNTDISABLE;
import static org.identityconnectors.common.CollectionUtil.newCaseInsensitiveSet;
import static org.identityconnectors.common.CollectionUtil.newSet;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ldap.LdapConnection;
import org.connid.bundles.ldap.commons.GroupHelper;
import org.connid.bundles.ldap.commons.LdapConstants;
import org.connid.bundles.ldap.commons.LdapEntry;
import org.connid.bundles.ldap.commons.LdapUtil;
import org.connid.bundles.ldap.schema.LdapSchemaMapping;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;

public class ADUtilities {

    private final Log LOG = Log.getLog(ADUtilities.class);

    private ADConnection connection;

    private GroupHelper groupHelper;

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
                final List<String> ldapGroups = groupHelper.getLdapGroups(entry.getDN().toString());
                attribute = AttributeBuilder.build(LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attributeName)) {
                final Set<String> posixRefAttrs =
                        LdapUtil.getStringAttrValues(entry.getAttributes(), GroupHelper.getPosixRefAttribute());
                final List<String> posixGroups = groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attributeName) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                // IMPORTANT!!! Return empty guarded string
                attribute = AttributeBuilder.build(attributeName, new GuardedString());
            } else if (UACCONTROL_ATTR.equals(attributeName) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                try {

                    final String status =
                            profile.get(UACCONTROL_ATTR) == null || profile.get(UACCONTROL_ATTR).get() == null
                            ? null : profile.get(UACCONTROL_ATTR).get().toString();

                    if (LOG.isOk()) {
                        LOG.ok("User Account Control: {0}", status);
                    }

                    // enabled if UF_ACCOUNTDISABLE is not included (0x00002)
                    if (status == null || Integer.parseInt(
                            profile.get(UACCONTROL_ATTR).get().toString())
                            % 16 != UF_ACCOUNTDISABLE) {
                        attribute = AttributeBuilder.buildEnabled(true);
                    } else {
                        attribute = AttributeBuilder.buildEnabled(false);
                    }

                } catch (NamingException e) {
                    LOG.error(e, "While fetching " + UACCONTROL_ATTR);
                }
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

    public ConnectorObject createDeletedObject(
            final String baseDN,
            final Uid uid,
            final Attributes profile,
            final ObjectClass oclass)
            throws NamingException {

        final LdapEntry entry = LdapEntry.create(baseDN, profile);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);

        builder.setUid(uid);
        builder.setName("fake-dn");
        builder.addAttributes(Collections.<Attribute>emptySet());

        return builder.build();
    }

    /**
     * Create a DN string starting from a set attributes and a default people container. This method has to be used if
     * __NAME__ attribute is not provided or it it is not a DN.
     *
     * @param attrs set of user attributes.
     * @param defaulContainer default people container.
     * @return distinguished name string.
     */
    public final String getDN(final ObjectClass oclass, final Set<Attribute> attrs) {

        String cn;

        final Attribute cnAttr = AttributeUtil.find("cn", attrs);

        if (cnAttr == null || cnAttr.getValue() == null
                || cnAttr.getValue().isEmpty()
                || StringUtil.isBlank(cnAttr.getValue().get(0).toString())) {
            // Get the name attribute and consider this as the principal name.
            // Use the principal name as the CN to generate DN.
            cn = AttributeUtil.getNameFromAttributes(attrs).getNameValue();
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
}
