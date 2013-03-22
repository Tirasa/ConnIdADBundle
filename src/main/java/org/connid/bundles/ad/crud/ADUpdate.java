/**
 * ==================== DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved. Copyright 2011-2013 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development and Distribution License("CDDL") (the
 * "License"). You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at https://oss.oracle.com/licenses/CDDL See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file and include the License file at
 * https://oss.oracle.com/licenses/CDDL. If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information: "Portions Copyrighted [year] [name of copyright
 * owner]" ====================
 */
package org.connid.bundles.ad.crud;

import static org.connid.bundles.ad.ADConnector.*;
import static org.connid.bundles.ldap.commons.LdapUtil.checkedListByFilter;
import static org.identityconnectors.common.CollectionUtil.isEmpty;
import static org.identityconnectors.common.CollectionUtil.newSet;
import static org.identityconnectors.common.CollectionUtil.nullAsEmpty;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.util.ADGuardedPasswordAttribute;
import org.connid.bundles.ad.util.ADGuardedPasswordAttribute.Accessor;
import org.connid.bundles.ad.util.ADUtilities;
import org.connid.bundles.ldap.commons.GroupHelper.GroupMembership;
import org.connid.bundles.ldap.commons.GroupHelper.Modification;
import org.connid.bundles.ldap.commons.LdapConstants;
import org.connid.bundles.ldap.commons.LdapModifyOperation;
import org.connid.bundles.ldap.search.LdapFilter;
import org.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;

public class ADUpdate extends LdapModifyOperation {

    private static final Log LOG = Log.getLog(ADUpdate.class);

    private final ObjectClass oclass;

    private Uid uid;

    @SuppressWarnings("FieldNameHidesFieldInSuperclass")
    private ADConnection conn;

    public ADUpdate(
            final ADConnection conn, final ObjectClass oclass, final Uid uid) {

        super(conn);
        this.oclass = oclass;
        this.uid = uid;
        this.conn = conn;
    }

    public Uid update(final Set<Attribute> attrs) {
        final ConnectorObject obj = getEntryToBeUpdated();
        String entryDN = obj.getName().getNameValue();

        // ---------------------------------
        // Check if entry should be renamed.
        // ---------------------------------
        final Name name = (Name) AttributeUtil.find(Name.NAME, attrs);

        Set<Attribute> attrToBeUpdated = attrs;

        Name newName = null;

        if (name != null) {
            attrToBeUpdated = newSet(attrs);
            attrToBeUpdated.remove(name);

            final ADUtilities utils = new ADUtilities((ADConnection) conn);

            if (utils.isDN(name.getNameValue())) {
                newName = new Name(conn.getSchemaMapping().getEntryDN(oclass, name));
            } else {
                try {

                    final List<Rdn> rdns = new ArrayList<Rdn>(new LdapName(entryDN).getRdns());

                    if (!rdns.get(rdns.size() - 1).getValue().toString().equalsIgnoreCase(name.getNameValue())) {
                        Rdn naming = new Rdn(rdns.get(rdns.size() - 1).getType(), name.getNameValue());
                        rdns.remove(rdns.size() - 1);
                        rdns.add(naming);

                        newName = new Name(new LdapName(rdns).toString());
                    }

                } catch (InvalidNameException e) {
                    LOG.error("Error retrieving new DN. Ignore rename request.", e);
                }
            }
        }
        // ---------------------------------

        // ---------------------------------
        // Perform modify/rename
        // ---------------------------------
        final Pair<Attributes, ADGuardedPasswordAttribute> attrToModify = getAttributesToModify(obj, attrToBeUpdated);

        final Attributes ldapAttrs = attrToModify.first;

        // Update the attributes.
        modifyAttributes(entryDN, attrToModify, DirContext.REPLACE_ATTRIBUTE);

        // Rename the entry if needed.
        if (newName != null) {
            entryDN = conn.getSchemaMapping().rename(oclass, entryDN, newName);
        }
        // ---------------------------------

        // ---------------------------------
        // Perform group memberships
        // ---------------------------------
        final List<String> ldapGroups = getStringListValue(attrToBeUpdated, LdapConstants.LDAP_GROUPS_NAME);

        if (ldapGroups != null) {
            final Set<String> oldMemberships = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            oldMemberships.addAll(groupHelper.getLdapGroups(entryDN));

            final Set<String> newMemberships = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            newMemberships.addAll(ldapGroups);

            // Update the LDAP groups.
            final Modification<GroupMembership> ldapGroupMod = new Modification<GroupMembership>();

            if (!newMemberships.equals(oldMemberships)) {
                oldMemberships.addAll(newMemberships);

                for (String membership : oldMemberships) {
                    ldapGroupMod.remove(new GroupMembership(entryDN, membership));
                }

                for (String membership : newMemberships) {
                    ldapGroupMod.add(new GroupMembership(entryDN, membership));
                }
            }

            groupHelper.modifyLdapGroupMemberships(ldapGroupMod);
        }
        // ---------------------------------

        return conn.getSchemaMapping().createUid(oclass, entryDN);
    }

    public Uid addAttributeValues(Set<Attribute> attrs) {
        final ConnectorObject obj = getEntryToBeUpdated();
        final String entryDN = obj.getName().getNameValue();

        final Pair<Attributes, ADGuardedPasswordAttribute> attrsToModify = getAttributesToModify(obj, attrs);

        modifyAttributes(entryDN, attrsToModify, DirContext.ADD_ATTRIBUTE);

        List<String> ldapGroups = getStringListValue(attrs, LdapConstants.LDAP_GROUPS_NAME);
        if (!isEmpty(ldapGroups)) {
            groupHelper.addLdapGroupMemberships(entryDN, ldapGroups);
        }

        return uid;
    }

    public Uid removeAttributeValues(Set<Attribute> attrs) {
        final ConnectorObject obj = getEntryToBeUpdated();
        final String entryDN = obj.getName().getNameValue();

        final Pair<Attributes, ADGuardedPasswordAttribute> attrsToModify = getAttributesToModify(obj, attrs);

        Attributes ldapAttrs = attrsToModify.first;

        modifyAttributes(entryDN, attrsToModify, DirContext.REMOVE_ATTRIBUTE);

        List<String> ldapGroups = getStringListValue(attrs, LdapConstants.LDAP_GROUPS_NAME);
        if (!isEmpty(ldapGroups)) {
            groupHelper.removeLdapGroupMemberships(entryDN, ldapGroups);
        }

        return uid;
    }

    private Pair<Attributes, ADGuardedPasswordAttribute> getAttributesToModify(
            final ConnectorObject obj, final Set<Attribute> attrs) {

        final BasicAttributes ldapAttrs = new BasicAttributes();
        ADGuardedPasswordAttribute pwdAttr = null;

        for (Attribute attr : attrs) {
            javax.naming.directory.Attribute ldapAttr = null;
            if (attr.is(Uid.NAME)) {

                throw new IllegalArgumentException("Unable to modify an object's uid");

            } else if (attr.is(Name.NAME)) {

                // Such a change would have been handled in update() above.
                throw new IllegalArgumentException("Unable to modify an object's name");

            } else if (attr.is(ADConfiguration.PROMPT_USER_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty() && (Boolean) value.get(0)) {
                    ldapAttrs.put(
                            new BasicAttribute(ADConfiguration.PROMPT_USER_FLAG, ADConfiguration.PROMPT_USER_VALUE));
                }
            } else if (LdapConstants.isLdapGroups(attr.getName())) {
                // Handled elsewhere.
            } else if (attr.is(OperationalAttributes.PASSWORD_NAME)) {

                pwdAttr = ADGuardedPasswordAttribute.create(conn.getConfiguration().getPasswordAttribute(), attr);

            } else if (attr.is(OperationalAttributes.ENABLE_NAME)) {
                final Attribute uac = obj.getAttributeByName(UACCONTROL_ATTR);

                int uacValue = uac != null && uac.getValue() != null && !uac.getValue().isEmpty()
                        ? Integer.parseInt(uac.getValue().get(0).toString()) : 0;

                boolean enabled = attr.getValue() == null
                        || attr.getValue().isEmpty() || Boolean.parseBoolean(attr.getValue().get(0).toString());

                if (enabled) {
                    // if not enabled yet --> enable removing 0x00002
                    if (uacValue % 16 == UF_ACCOUNTDISABLE) {
                        uacValue -= UF_ACCOUNTDISABLE;
                    }
                } else {
                    // if not disabled yet --> disable adding 0x00002
                    if (uacValue % 16 != UF_ACCOUNTDISABLE) {
                        uacValue += UF_ACCOUNTDISABLE;
                    }
                }

                ldapAttr = conn.getSchemaMapping().encodeAttribute(
                        oclass, AttributeBuilder.build(UACCONTROL_ATTR, Integer.toString(uacValue)));
            } else {
                ldapAttr = conn.getSchemaMapping().encodeAttribute(oclass, attr);
            }

            if (ldapAttr != null) {
                final javax.naming.directory.Attribute existingAttr = ldapAttrs.get(ldapAttr.getID());

                if (existingAttr != null) {
                    try {
                        NamingEnumeration<?> all = ldapAttr.getAll();
                        while (all.hasMoreElements()) {
                            existingAttr.add(all.nextElement());
                        }
                    } catch (NamingException e) {
                        throw new ConnectorException(e);
                    }
                } else {
                    ldapAttrs.put(ldapAttr);
                }
            }
        }

        return new Pair<Attributes, ADGuardedPasswordAttribute>(
                ldapAttrs, pwdAttr);
    }

    private void modifyAttributes(
            final String entryDN,
            final Pair<Attributes, ADGuardedPasswordAttribute> attrs,
            final int modifyOp) {

        final List<ModificationItem> modItems = new ArrayList<ModificationItem>(attrs.first.size());

        NamingEnumeration<? extends javax.naming.directory.Attribute> attrEnum = attrs.first.getAll();

        while (attrEnum.hasMoreElements()) {
            modItems.add(new ModificationItem(modifyOp, attrEnum.nextElement()));
        }

        if (attrs.second != null) {
            attrs.second.access(new Accessor() {

                @Override
                public void access(BasicAttribute attr) {
                    try {
                        if (attr.get() != null) {
                            modItems.add(new ModificationItem(modifyOp, attr));
                            modifyAttributes(entryDN, modItems);
                        }
                    } catch (NamingException e) {
                        LOG.error(e, "Error retrieving password value");
                    }
                }
            });
        }

        modifyAttributes(entryDN, modItems);
    }

    private void modifyAttributes(
            final String entryDN, final List<ModificationItem> modItems) {
        try {
            conn.getInitialContext().modifyAttributes(entryDN, modItems.toArray(new ModificationItem[modItems.size()]));
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    private List<String> getStringListValue(
            final Set<Attribute> attrs, final String attrName) {
        final Attribute attr = AttributeUtil.find(attrName, attrs);

        if (attr != null) {
            return checkedListByFilter(nullAsEmpty(attr.getValue()), String.class);
        }

        return null;
    }

    private ConnectorObject getEntryToBeUpdated() {
        final String filter = conn.getConfiguration().getUidAttribute() + "=" + uid.getUidValue();

        final ConnectorObject obj = LdapSearches.findObject(
                conn, oclass, LdapFilter.forNativeFilter(filter), UACCONTROL_ATTR);

        if (obj == null) {
            throw new ConnectorException("Entry not found");
        }

        return obj;
    }
}
