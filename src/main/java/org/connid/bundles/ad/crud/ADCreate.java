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
package org.connid.bundles.ad.crud;

import static org.connid.bundles.ad.ADConnector.UF_ACCOUNTDISABLE;
import static org.connid.bundles.ad.ADConnector.UF_NORMAL_ACCOUNT;
import static org.connid.bundles.ldap.commons.LdapUtil.checkedListByFilter;
import static org.identityconnectors.common.CollectionUtil.isEmpty;
import static org.identityconnectors.common.CollectionUtil.nullAsEmpty;

import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.util.ADGuardedPasswordAttribute;
import org.connid.bundles.ad.util.ADGuardedPasswordAttribute.Accessor;
import org.connid.bundles.ad.util.ADUtilities;
import org.connid.bundles.ldap.commons.LdapConstants;
import org.connid.bundles.ldap.commons.LdapModifyOperation;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;

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

        // -------------------------------------------------
        // Retrieve DN
        // -------------------------------------------------
        final Name nameAttr = AttributeUtil.getNameFromAttributes(attrs);

        if (nameAttr == null) {
            throw new IllegalArgumentException("No Name attribute provided in the attributes");
        }

        final ADUtilities utils = new ADUtilities((ADConnection) conn);

        Name name;

        if (utils.isDN(nameAttr.getNameValue())) {
            name = nameAttr;
        } else {

            Uid uidAttr = AttributeUtil.getUidAttribute(attrs);

            if (uidAttr == null && StringUtil.isNotBlank(nameAttr.getNameValue())) {
                uidAttr = new Uid(nameAttr.getNameValue());
                attrs.add(uidAttr);
            }

            name = new Name(utils.getDN(attrs));

        }
        // -------------------------------------------------

        List<String> ldapGroups = null;

        ADGuardedPasswordAttribute pwdAttr = null;

        final BasicAttributes adAttrs = new BasicAttributes(true);

        boolean enabled = true;

        for (Attribute attr : attrs) {
            javax.naming.directory.Attribute ldapAttr = null;

            if (attr.is(Name.NAME)) {
                // Handled already.
            } else if (attr.is(ADConfiguration.PROMPT_USER_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty() && (Boolean) value.get(0)) {
                    adAttrs.put(
                            new BasicAttribute(ADConfiguration.PROMPT_USER_FLAG, ADConfiguration.PROMPT_USER_VALUE));
                }
            } else if (attr.is(ADConfiguration.LOCK_OUT_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty() && (Boolean) value.get(0)) {
                    adAttrs.put(
                            new BasicAttribute(ADConfiguration.LOCK_OUT_FLAG, ADConfiguration.LOCK_OUT_DEFAULT_VALUE));
                }
            } else if (LdapConstants.isLdapGroups(attr.getName())) {

                ldapGroups = checkedListByFilter(nullAsEmpty(attr.getValue()), String.class);

            } else if (attr.is(OperationalAttributes.PASSWORD_NAME)) {

                pwdAttr = ADGuardedPasswordAttribute.create(conn.getConfiguration().getPasswordAttribute(), attr);

            } else if (attr.is(OperationalAttributes.ENABLE_NAME)) {
                enabled = attr.getValue() == null || attr.getValue().isEmpty()
                        || Boolean.parseBoolean(attr.getValue().get(0).toString());
            } else {
                ldapAttr = conn.getSchemaMapping().encodeAttribute(oclass, attr);

                // Do not send empty attributes. 
                if (ldapAttr != null && ldapAttr.size() > 0) {
                    adAttrs.put(ldapAttr);
                }
            }
        }

        final String[] entryDN = new String[1];

        final String pwdAttrName = conn.getConfiguration().getPasswordAttribute();

        if (pwdAttr != null) {
            pwdAttr.access(new Accessor() {

                @Override
                public void access(BasicAttribute attr) {
                    try {
                        if (attr.get() != null && !attr.get().toString().isEmpty()) {
                            adAttrs.put(attr);
                        }
                    } catch (NamingException e) {
                        LOG.error(e, "Error retrieving password value");
                    }
                }
            });
        }

        if (enabled && adAttrs.get(pwdAttrName) != null) {
            adAttrs.put("userAccountControl", Integer.toString(UF_NORMAL_ACCOUNT));
        } else {
            adAttrs.put("userAccountControl", Integer.toString(UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE));
        }

        entryDN[0] = conn.getSchemaMapping().create(oclass, name, adAttrs);

        if (!isEmpty(ldapGroups)) {
            groupHelper.addLdapGroupMemberships(entryDN[0], ldapGroups);
        }

        return conn.getSchemaMapping().createUid(oclass, entryDN[0]);
    }
}
