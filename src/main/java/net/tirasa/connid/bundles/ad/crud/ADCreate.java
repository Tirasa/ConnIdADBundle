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
package net.tirasa.connid.bundles.ad.crud;

import static net.tirasa.connid.bundles.ad.ADConnector.OBJECTGUID;
import static net.tirasa.connid.bundles.ad.ADConnector.UACCONTROL_ATTR;
import static net.tirasa.connid.bundles.ad.ADConnector.UF_ACCOUNTDISABLE;
import static net.tirasa.connid.bundles.ad.ADConnector.UF_NORMAL_ACCOUNT;
import static net.tirasa.connid.bundles.ldap.commons.LdapUtil.checkedListByFilter;
import static org.identityconnectors.common.CollectionUtil.isEmpty;
import static org.identityconnectors.common.CollectionUtil.nullAsEmpty;

import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ad.ADConnector;
import net.tirasa.connid.bundles.ad.util.ADGuardedPasswordAttribute;
import net.tirasa.connid.bundles.ad.util.ADUtilities;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.modify.LdapCreate;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import net.tirasa.connid.bundles.ldap.schema.GuardedPasswordAttribute.Accessor;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;

public class ADCreate extends LdapCreate {

    private static final Log LOG = Log.getLog(ADConnection.class);

    public ADCreate(
            final ADConnection conn,
            final ObjectClass oclass,
            final Set<Attribute> attrs,
            final OperationOptions options) {
        super(conn, oclass, attrs, options);
    }

    @Override
    protected Uid executeImpl() throws NamingException {

        // -------------------------------------------------
        // Retrieve DN
        // -------------------------------------------------
        final Name nameAttr = AttributeUtil.getNameFromAttributes(attrs);

        if (nameAttr == null) {
            throw new IllegalArgumentException("No Name attribute provided in the attributes");
        }

        final Attribute cnAttr = AttributeUtil.find(ADConfiguration.CN_NAME, attrs);
        if (cnAttr != null) {
            attrs.remove(cnAttr);
        }

        final ADUtilities utils = new ADUtilities((ADConnection) conn);

        Name name;
        Uid uid = AttributeUtil.getUidAttribute(attrs);

        if (ADUtilities.isDN(nameAttr.getNameValue())) {
            name = nameAttr;
        } else {
            if (uid == null && StringUtil.isNotBlank(nameAttr.getNameValue())) {
                uid = new Uid(nameAttr.getNameValue());
                attrs.add(uid);
            }

            name = new Name(utils.getDN(oclass, nameAttr, cnAttr));
        }
        // -------------------------------------------------

        // -------------------------------------------------
        // Add gid/uidAttribute if missing and if value is available
        // -------------------------------------------------
        final String idAttrName;
        if (ObjectClass.ACCOUNT.equals(oclass)) {
            idAttrName = conn.getConfiguration().getUidAttribute();
        } else if (ObjectClass.GROUP.equals(oclass)) {
            idAttrName = conn.getConfiguration().getGidAttribute();
        } else if (LdapSchema.ANY_OBJECT_CLASS.equals(oclass)) {
            idAttrName = conn.getConfiguration().getAoidAttribute();
        } else {
            idAttrName = ADConfiguration.class.cast(conn.getConfiguration()).getDefaultIdAttribute();
        }

        final Attribute idAttr = AttributeUtil.find(idAttrName, attrs);

        if ((idAttr == null || CollectionUtil.isEmpty(idAttr.getValue())) && uid != null) {
            attrs.add(AttributeBuilder.build(idAttrName, uid.getUidValue()));
        }
        // -------------------------------------------------

        List<String> ldapGroups = null;

        String primaryGroupDN = null;

        ADGuardedPasswordAttribute pwdAttr = null;

        final BasicAttributes adAttrs = new BasicAttributes(true);

        int uacValue = UF_NORMAL_ACCOUNT;

        Boolean uccp = null;
        Boolean pne = null;
        Boolean pnr = null;
        Boolean status = null;

        for (Attribute attr : attrs) {

            if (attr.is(Name.NAME)) {
                // Handled already.
            } else if (attr.is(ADConfiguration.UCCP_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty()) {
                    uccp = (Boolean) value.get(0);
                }
            } else if (attr.is(ADConfiguration.PNE_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty()) {
                    pne = (Boolean) value.get(0);
                }
            } else if (attr.is(ADConfiguration.PNR_FLAG)) {
                final List<Object> value = attr.getValue();
                if (value != null && !value.isEmpty()) {
                    pnr = (Boolean) value.get(0);
                }
            } else if (attr.is(ADConfiguration.PRIMARY_GROUP_DN_NAME)) {
                final List<Object> value = attr.getValue();
                primaryGroupDN = value == null || value.isEmpty() ? null : String.class.cast(value.get(0));
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

            } else if (attr.is(UACCONTROL_ATTR) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                uacValue = attr.getValue() == null || attr.getValue().isEmpty()
                        ? UF_NORMAL_ACCOUNT
                        : Integer.parseInt(attr.getValue().get(0).toString());
            } else if (attr.is(OperationalAttributes.ENABLE_NAME) && oclass.is(ObjectClass.ACCOUNT_NAME)) {
                status = attr.getValue() == null
                        || attr.getValue().isEmpty()
                        || Boolean.parseBoolean(attr.getValue().get(0).toString());
            } else if (attr.is(OBJECTGUID)) {
                // ignore info
            } else {
                javax.naming.directory.Attribute ldapAttr = conn.getSchema().encodeAttribute(oclass, attr);

                // Do not send empty attributes. 
                if (ldapAttr != null && ldapAttr.size() > 0) {
                    adAttrs.put(ldapAttr);
                }
            }
        }

        final String pwdAttrName = conn.getConfiguration().getPasswordAttribute();

        if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
            if (pne != null) {
                if ((uacValue & ADConnector.UF_DONT_EXPIRE_PASSWD) == ADConnector.UF_DONT_EXPIRE_PASSWD && !pne) {
                    uacValue -= ADConnector.UF_DONT_EXPIRE_PASSWD;
                } else if ((uacValue & ADConnector.UF_DONT_EXPIRE_PASSWD) != ADConnector.UF_DONT_EXPIRE_PASSWD && pne) {
                    uacValue = uacValue == -1
                            ? ADConnector.UF_DONT_EXPIRE_PASSWD
                            : uacValue + ADConnector.UF_DONT_EXPIRE_PASSWD;
                }
            }

            if (pnr != null) {
                if ((uacValue & ADConnector.UF_PASSWD_NOTREQD) == ADConnector.UF_PASSWD_NOTREQD && !pnr) {
                    uacValue -= ADConnector.UF_PASSWD_NOTREQD;
                } else if ((uacValue & ADConnector.UF_PASSWD_NOTREQD) != ADConnector.UF_PASSWD_NOTREQD && pnr) {
                    uacValue = uacValue == -1
                            ? ADConnector.UF_PASSWD_NOTREQD
                            : uacValue + ADConnector.UF_PASSWD_NOTREQD;
                }
            }

            if (status != null) {
                if ((uacValue & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE && status) {
                    uacValue -= UF_ACCOUNTDISABLE;
                } else if ((uacValue & UF_ACCOUNTDISABLE) != UF_ACCOUNTDISABLE && !status) {
                    uacValue = uacValue == -1
                            ? UF_ACCOUNTDISABLE
                            : uacValue + UF_ACCOUNTDISABLE;
                }
            }

            if (pwdAttr != null) {
                pwdAttr.access(new Accessor() {

                    @Override
                    public void access(javax.naming.directory.Attribute attr) {
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

            if (adAttrs.get(pwdAttrName) == null) {
                if ((uacValue & UF_ACCOUNTDISABLE) != UF_ACCOUNTDISABLE) {
                    uacValue += UF_ACCOUNTDISABLE;
                }
            }

            adAttrs.put(UACCONTROL_ATTR, Integer.toString(uacValue));
        }

        final String entryDN = conn.getSchema().create(oclass, name, adAttrs);

        if (uccp != null) {
            // ---------------------------------
            // Change ntSecurityDescriptor
            // ---------------------------------
            conn.getInitialContext().modifyAttributes(entryDN, new ModificationItem[] {
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE, utils.userCannotChangePassword(entryDN, uccp)) });

            // ---------------------------------
        }

        if (!isEmpty(ldapGroups)) {
            groupHelper.addLdapGroupMemberships(entryDN, ldapGroups);
        }

        if (StringUtil.isNotBlank(primaryGroupDN)) {
            // ---------------------------------
            // Change primaryGroupID
            // ---------------------------------
            conn.getInitialContext().modifyAttributes(entryDN, new ModificationItem[] {
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE, utils.getGroupID(primaryGroupDN)) });

            // ---------------------------------
        }

        if (OBJECTGUID.equals(conn.getSchema().getLdapUidAttribute(oclass))) {
            final Attributes profile = conn.getInitialContext().getAttributes(entryDN, new String[] { OBJECTGUID });
            return new Uid(GUID.getGuidAsString((byte[]) profile.get(OBJECTGUID).get()));
        } else {
            return conn.getSchema().createUid(oclass, entryDN);
        }
    }
}
