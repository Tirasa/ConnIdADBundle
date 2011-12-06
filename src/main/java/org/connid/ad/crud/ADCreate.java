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

import static org.identityconnectors.common.CollectionUtil.isEmpty;
import static org.identityconnectors.common.CollectionUtil.nullAsEmpty;
import static org.identityconnectors.ldap.LdapUtil.checkedListByFilter;
import static org.connid.ad.ADConnector.*;

import java.util.List;
import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.connid.ad.ADConnection;
import org.connid.ad.util.ADGuardedPasswordAttribute;
import org.connid.ad.util.ADGuardedPasswordAttribute.Accessor;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapModifyOperation;
import org.identityconnectors.ldap.LdapConstants;

public class ADCreate extends LdapModifyOperation {

    private static final Log LOG = Log.getLog(ADConnection.class);

    private final ObjectClass oclass;

    private final Set<Attribute> attrs;

    @SuppressWarnings("FieldNameHidesFieldInSuperclass")
    private final ADConnection conn;

    public ADCreate(
            final ADConnection conn,
            final ObjectClass oclass,
            final Set<Attribute> attrs,
            final OperationOptions options) {
        super(conn);

        this.oclass = oclass;
        this.attrs = attrs;
        this.conn = conn;
    }

    public Uid create() {
        try {
            return executeImpl();
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    private Uid executeImpl()
            throws NamingException {

        final Name nameAttr = AttributeUtil.getNameFromAttributes(attrs);

        if (nameAttr == null) {
            throw new IllegalArgumentException(
                    "No Name attribute provided in the attributes");
        }

        List<String> ldapGroups = null;
        List<String> posixGroups = null;

        ADGuardedPasswordAttribute pwdAttr = null;

        final BasicAttributes adAttrs = new BasicAttributes(true);

        boolean enabled = true;

        for (Attribute attr : attrs) {
            javax.naming.directory.Attribute ldapAttr = null;

            if (attr.is(Name.NAME)) {
                // Handled already.
            } else if (LdapConstants.isLdapGroups(attr.getName())) {

                ldapGroups = checkedListByFilter(
                        nullAsEmpty(attr.getValue()), String.class);

            } else if (LdapConstants.isPosixGroups(attr.getName())) {

                posixGroups = checkedListByFilter(
                        nullAsEmpty(attr.getValue()), String.class);

            } else if (attr.is(OperationalAttributes.PASSWORD_NAME)) {

                pwdAttr = ADGuardedPasswordAttribute.create(
                        conn.getConfiguration().getPasswordAttribute(),
                        attr);

            } else if (attr.is(OperationalAttributes.ENABLE_NAME)) {
                enabled = attr.getValue() == null || attr.getValue().isEmpty()
                        || Boolean.parseBoolean(
                        attr.getValue().get(0).toString());
            } else {
                ldapAttr = conn.getSchemaMapping().encodeAttribute(oclass,
                        attr);

                // Do not send empty attributes. 
                if (ldapAttr != null && ldapAttr.size() > 0) {
                    adAttrs.put(ldapAttr);
                }
            }
        }

        final String[] entryDN = new String[1];

        final String pwdAttrName =
                conn.getConfiguration().getPasswordAttribute();

        if (pwdAttr != null) {
            pwdAttr.access(new Accessor() {

                @Override
                public void access(BasicAttribute attr) {
                    try {
                        if (attr.get() != null
                                && !attr.get().toString().isEmpty()) {

                            adAttrs.put(attr);
                        }
                    } catch (NamingException e) {
                        LOG.error(e, "Error retrieving password value");
                    }
                }
            });
        }

        if (enabled && adAttrs.get(pwdAttrName) != null) {
            adAttrs.put(
                    "userAccountControl",
                    Integer.toString(UF_NORMAL_ACCOUNT));
        } else {
            adAttrs.put(
                    "userAccountControl",
                    Integer.toString(UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE));
        }

        entryDN[0] = conn.getSchemaMapping().create(oclass, nameAttr, adAttrs);

        if (!isEmpty(ldapGroups)) {
            groupHelper.addLdapGroupMemberships(entryDN[0], ldapGroups);
        }

        if (!isEmpty(posixGroups)) {
            final Set<String> posixRefAttrs = getAttributeValues(
                    GroupHelper.getPosixRefAttribute(), null, adAttrs);

            final String posixRefAttr =
                    getFirstPosixRefAttr(entryDN[0], posixRefAttrs);

            groupHelper.addPosixGroupMemberships(posixRefAttr, posixGroups);
        }

        return conn.getSchemaMapping().createUid(oclass, entryDN[0]);
    }
}
