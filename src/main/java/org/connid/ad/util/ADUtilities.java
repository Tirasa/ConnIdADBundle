/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2011 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License. You can obtain
 * a copy of the License at https://glassfish.dev.java.net/public/CDDL+GPL.html
 * or glassfish/bootstrap/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/bootstrap/legal/LICENSE.txt.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.  If applicable, add the following below the License
 * Header, with the fields enclosed by brackets [] replaced by your own
 * identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 */
package org.connid.ad.util;

import static org.connid.ad.ADConnector.*;

import java.util.List;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import org.connid.ad.ADConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapConstants;
import org.identityconnectors.ldap.LdapEntry;
import org.identityconnectors.ldap.LdapUtil;

public class ADUtilities {

    private final Log LOG = Log.getLog(ADUtilities.class);

    private ADConnection connection;

    private GroupHelper groupHelper;

    public ADUtilities(final ADConnection connection) {
        this.connection = connection;
        groupHelper = new GroupHelper(connection);
    }

    public ConnectorObject createConnectorObject(
            final String baseDN,
            final Attributes profile,
            final ObjectClass oclass)
            throws NamingException {

        final LdapEntry entry = LdapEntry.create(baseDN, profile);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);

        builder.setUid(connection.getSchemaMapping().createUid(oclass, entry));
        builder.setName(connection.getSchemaMapping().createName(oclass, entry));

        final NamingEnumeration<String> attributeNames = profile.getIDs();

        while (attributeNames.hasMoreElements()) {
            final String attributeName = attributeNames.next();

            Attribute attribute = null;

            if (LdapConstants.isLdapGroups(attributeName)) {
                final List<String> ldapGroups =
                        groupHelper.getLdapGroups(entry.getDN().toString());
                attribute = AttributeBuilder.build(
                        LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attributeName)) {
                final Set<String> posixRefAttrs =
                        LdapUtil.getStringAttrValues(entry.getAttributes(),
                        GroupHelper.getPosixRefAttribute());
                final List<String> posixGroups =
                        groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(
                        LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attributeName)) {
                // IMPORTANT!!! Return empty guarded string
                attribute = AttributeBuilder.build(
                        attributeName, new GuardedString());
            } else if (UACCONTROL_ATTR.equals(attributeName)) {
                try {

                    final String status =
                            profile.get(UACCONTROL_ATTR).get() != null
                            ? profile.get(UACCONTROL_ATTR).get().
                            toString()
                            : null;

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
                attribute = connection.getSchemaMapping().createAttribute(
                        oclass, attributeName, entry, false);
            }

            // Avoid attribute adding in case of attribute name not found
            if (attribute != null) {
                builder.addAttribute(attribute);
            }
        }

        return builder.build();
    }
}
