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

import static org.connid.ad.ADConnector.*;

import static org.identityconnectors.common.CollectionUtil.isEmpty;
import static org.identityconnectors.common.CollectionUtil.newSet;
import static org.identityconnectors.common.CollectionUtil.nullAsEmpty;
import static org.identityconnectors.ldap.LdapUtil.checkedListByFilter;
import static org.identityconnectors.ldap.LdapUtil.quietCreateLdapName;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

import org.connid.ad.ADConnection;
import org.connid.ad.util.ADGuardedPasswordAttribute;
import org.connid.ad.util.ADGuardedPasswordAttribute.Accessor;
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
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapModifyOperation;
import org.identityconnectors.ldap.LdapConstants;
import org.identityconnectors.ldap.GroupHelper.GroupMembership;
import org.identityconnectors.ldap.GroupHelper.Modification;
import org.identityconnectors.ldap.search.LdapFilter;
import org.identityconnectors.ldap.search.LdapSearches;

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
        final String filter =
                conn.getConfiguration().getUidAttribute()
                + "="
                + uid.getUidValue();

        final ConnectorObject obj = LdapSearches.findObject(
                conn,
                oclass,
                LdapFilter.forNativeFilter(filter),
                UACCONTROL_ATTR);

        String entryDN = obj.getName().getNameValue();

        final PosixGroupMember posixMember = new PosixGroupMember(entryDN);

        // Extract the Name attribute if any, to be used to rename the entry later.
        Set<Attribute> updateAttrs = attrs;

        final Name newName = (Name) AttributeUtil.find(Name.NAME, attrs);

        String newEntryDN = null;

        if (newName != null) {
            updateAttrs = newSet(attrs);
            updateAttrs.remove(newName);
            newEntryDN = conn.getSchemaMapping().getEntryDN(oclass, newName);
        }

        final List<String> ldapGroups = getStringListValue(updateAttrs,
                LdapConstants.LDAP_GROUPS_NAME);
        final List<String> posixGroups = getStringListValue(updateAttrs,
                LdapConstants.POSIX_GROUPS_NAME);

        final Pair<Attributes, ADGuardedPasswordAttribute> attrToModify =
                getAttributesToModify(obj, updateAttrs);

        final Attributes ldapAttrs = attrToModify.first;

        // If we are removing all POSIX ref attributes, check they are not used
        // in POSIX groups. Note it is OK to update the POSIX ref attribute instead of
        // removing them -- we will update the groups to refer to the new attributes.
        final Set<String> newPosixRefAttrs = getAttributeValues(
                GroupHelper.getPosixRefAttribute(),
                quietCreateLdapName(newEntryDN != null ? newEntryDN : entryDN),
                ldapAttrs);

        if (newPosixRefAttrs != null && newPosixRefAttrs.isEmpty()) {
            checkRemovedPosixRefAttrs(posixMember.getPosixRefAttributes(),
                    posixMember.getPosixGroupMemberships());
        }

        // Update the attributes.
        modifyAttributes(entryDN, attrToModify, DirContext.REPLACE_ATTRIBUTE);

        // Rename the entry if needed.
        String oldEntryDN = null;
        if (newName != null) {
            if (newPosixRefAttrs != null && conn.getConfiguration().
                    isMaintainPosixGroupMembership() || posixGroups != null) {
                posixMember.getPosixRefAttributes();
            }
            oldEntryDN = entryDN;
            entryDN = conn.getSchemaMapping().rename(oclass, oldEntryDN, newName);
        }

        // Update the LDAP groups.
        final Modification<GroupMembership> ldapGroupMod =
                new Modification<GroupMembership>();

        if (oldEntryDN != null && conn.getConfiguration().
                isMaintainLdapGroupMembership()) {
            final Set<GroupMembership> members =
                    groupHelper.getLdapGroupMemberships(oldEntryDN);
            ldapGroupMod.removeAll(members);

            for (GroupMembership member : members) {
                ldapGroupMod.add(new GroupMembership(entryDN,
                        member.getGroupDN()));
            }
        }

        if (ldapGroups != null) {
            final Set<GroupMembership> members =
                    groupHelper.getLdapGroupMemberships(entryDN);

            ldapGroupMod.removeAll(members);
            ldapGroupMod.clearAdded(); // Since we will be replacing with the new groups.

            for (String ldapGroup : ldapGroups) {
                ldapGroupMod.add(new GroupMembership(entryDN, ldapGroup));
            }
        }

        groupHelper.modifyLdapGroupMemberships(ldapGroupMod);

        // Update the POSIX groups.
        final Modification<GroupMembership> posixGroupMod =
                new Modification<GroupMembership>();

        if (newPosixRefAttrs != null && conn.getConfiguration().
                isMaintainPosixGroupMembership()) {
            final Set<String> removedPosixRefAttrs =
                    new HashSet<String>(posixMember.getPosixRefAttributes());

            removedPosixRefAttrs.removeAll(newPosixRefAttrs);

            final Set<GroupMembership> members =
                    posixMember.getPosixGroupMembershipsByAttrs(
                    removedPosixRefAttrs);

            posixGroupMod.removeAll(members);

            if (!members.isEmpty()) {
                for (GroupMembership member : members) {
                    posixGroupMod.add(new GroupMembership(
                            getFirstPosixRefAttr(entryDN, newPosixRefAttrs),
                            member.getGroupDN()));
                }
            }
        }

        if (posixGroups != null) {
            final Set<GroupMembership> members =
                    posixMember.getPosixGroupMemberships();
            posixGroupMod.removeAll(members);

            // Since we will be replacing with the new groups.
            posixGroupMod.clearAdded();

            if (!posixGroups.isEmpty()) {
                for (String posixGroup : posixGroups) {
                    posixGroupMod.add(new GroupMembership(
                            getFirstPosixRefAttr(entryDN, newPosixRefAttrs),
                            posixGroup));
                }
            }
        }
        groupHelper.modifyPosixGroupMemberships(posixGroupMod);

        return conn.getSchemaMapping().createUid(oclass, entryDN);
    }

    public Uid addAttributeValues(Set<Attribute> attrs) {
        final String filter =
                conn.getConfiguration().getUidAttribute()
                + "="
                + uid.getUidValue();

        final ConnectorObject obj = LdapSearches.findObject(
                conn,
                oclass,
                LdapFilter.forNativeFilter(filter),
                UACCONTROL_ATTR);

        String entryDN = obj.getName().getNameValue();

        final PosixGroupMember posixMember = new PosixGroupMember(entryDN);

        final Pair<Attributes, ADGuardedPasswordAttribute> attrsToModify =
                getAttributesToModify(obj, attrs);

        modifyAttributes(entryDN, attrsToModify, DirContext.ADD_ATTRIBUTE);

        List<String> ldapGroups = getStringListValue(attrs,
                LdapConstants.LDAP_GROUPS_NAME);
        if (!isEmpty(ldapGroups)) {
            groupHelper.addLdapGroupMemberships(entryDN, ldapGroups);
        }

        List<String> posixGroups = getStringListValue(attrs,
                LdapConstants.POSIX_GROUPS_NAME);
        if (!isEmpty(posixGroups)) {
            Set<String> posixRefAttrs = posixMember.getPosixRefAttributes();
            String posixRefAttr = getFirstPosixRefAttr(entryDN, posixRefAttrs);
            groupHelper.addPosixGroupMemberships(posixRefAttr, posixGroups);
        }

        return uid;
    }

    public Uid removeAttributeValues(Set<Attribute> attrs) {
        final String filter =
                conn.getConfiguration().getUidAttribute()
                + "="
                + uid.getUidValue();

        final ConnectorObject obj = LdapSearches.findObject(
                conn,
                oclass,
                LdapFilter.forNativeFilter(filter),
                UACCONTROL_ATTR);

        String entryDN = obj.getName().getNameValue();

        final PosixGroupMember posixMember = new PosixGroupMember(entryDN);

        final Pair<Attributes, ADGuardedPasswordAttribute> attrsToModify =
                getAttributesToModify(obj, attrs);

        Attributes ldapAttrs = attrsToModify.first;

        Set<String> removedPosixRefAttrs = getAttributeValues(GroupHelper.
                getPosixRefAttribute(), null, ldapAttrs);
        if (!isEmpty(removedPosixRefAttrs)) {
            checkRemovedPosixRefAttrs(removedPosixRefAttrs, posixMember.
                    getPosixGroupMemberships());
        }

        modifyAttributes(entryDN, attrsToModify, DirContext.REMOVE_ATTRIBUTE);

        List<String> ldapGroups = getStringListValue(attrs,
                LdapConstants.LDAP_GROUPS_NAME);
        if (!isEmpty(ldapGroups)) {
            groupHelper.removeLdapGroupMemberships(entryDN, ldapGroups);
        }

        List<String> posixGroups = getStringListValue(attrs,
                LdapConstants.POSIX_GROUPS_NAME);
        if (!isEmpty(posixGroups)) {
            Set<GroupMembership> members = posixMember.
                    getPosixGroupMembershipsByGroups(posixGroups);
            groupHelper.removePosixGroupMemberships(members);
        }

        return uid;
    }

    private void checkRemovedPosixRefAttrs(
            final Set<String> removedPosixRefAttrs,
            final Set<GroupMembership> memberships) {
        for (GroupMembership membership : memberships) {
            if (removedPosixRefAttrs.contains(membership.getMemberRef())) {
                throw new ConnectorException(conn.format(
                        "cannotRemoveBecausePosixMember", GroupHelper.
                        getPosixRefAttribute()));
            }
        }
    }

    private Pair<Attributes, ADGuardedPasswordAttribute> getAttributesToModify(
            final ConnectorObject obj, final Set<Attribute> attrs) {

        final BasicAttributes ldapAttrs = new BasicAttributes();
        ADGuardedPasswordAttribute pwdAttr = null;

        for (Attribute attr : attrs) {
            javax.naming.directory.Attribute ldapAttr = null;
            if (attr.is(Uid.NAME)) {

                throw new IllegalArgumentException(
                        "Unable to modify an object's uid");

            } else if (attr.is(Name.NAME)) {

                // Such a change would have been handled in update() above.
                throw new IllegalArgumentException(
                        "Unable to modify an object's name");

            } else if (LdapConstants.isLdapGroups(attr.getName())) {
                // Handled elsewhere.
            } else if (LdapConstants.isPosixGroups(attr.getName())) {
                // Handled elsewhere.
            } else if (attr.is(OperationalAttributes.PASSWORD_NAME)) {

                pwdAttr = ADGuardedPasswordAttribute.create(
                        conn.getConfiguration().getPasswordAttribute(), attr);

            } else if (attr.is(OperationalAttributes.ENABLE_NAME)) {
                final Attribute uac =
                        obj.getAttributeByName(UACCONTROL_ATTR);

                int uacValue =
                        uac != null
                        && uac.getValue() != null
                        && !uac.getValue().isEmpty()
                        ? Integer.parseInt(uac.getValue().get(0).toString())
                        : 0;

                boolean enabled = attr.getValue() == null || attr.getValue().
                        isEmpty()
                        || Boolean.parseBoolean(
                        attr.getValue().get(0).toString());

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
                        oclass,
                        AttributeBuilder.build(
                        UACCONTROL_ATTR, Integer.toString(uacValue)));
            } else {
                ldapAttr = conn.getSchemaMapping().encodeAttribute(
                        oclass,
                        attr);
            }

            if (ldapAttr != null) {
                final javax.naming.directory.Attribute existingAttr =
                        ldapAttrs.get(ldapAttr.getID());

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

        final List<ModificationItem> modItems =
                new ArrayList<ModificationItem>(attrs.first.size());

        NamingEnumeration<? extends javax.naming.directory.Attribute> attrEnum =
                attrs.first.getAll();

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
            conn.getInitialContext().modifyAttributes(
                    entryDN,
                    modItems.toArray(new ModificationItem[modItems.size()]));
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    private List<String> getStringListValue(
            final Set<Attribute> attrs, final String attrName) {
        final Attribute attr = AttributeUtil.find(attrName, attrs);

        if (attr != null) {
            return checkedListByFilter(nullAsEmpty(attr.getValue()),
                    String.class);
        }

        return null;
    }
}
