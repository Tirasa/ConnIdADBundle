/**
 * ====================
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
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
package org.connid.bundles.ad.schema;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.ADConnector;
import org.connid.bundles.ldap.search.LdapInternalSearch;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;

class ADSchemaBuilder {

    private static final Log LOG = Log.getLog(ADSchemaBuilder.class);

    private ADConnection connection;

    private Schema schema;

    private static String[] ATTRIBUTES_TO_GET = {
        "maycontain",
        "systemmaycontain",
        "mustcontain",
        "systemmustcontain"};

    public ADSchemaBuilder(final ADConnection connection) {
        this.connection = connection;
    }

    public Schema getSchema() {
        if (schema == null) {
            buildSchema();
        }
        return schema;
    }

    private void buildSchema() {
        final ADConfiguration conf =
                (ADConfiguration) connection.getConfiguration();

        final SchemaBuilder schemaBld = new SchemaBuilder(ADConnector.class);

        final StringBuilder filter = new StringBuilder();

        // -----------------------------------
        // Create search control
        // -----------------------------------
        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningAttributes(ATTRIBUTES_TO_GET);
        // -----------------------------------

        // -----------------------------------
        // Specify filter
        // -----------------------------------
        for (String oclass : conf.getAccountObjectClasses()) {
            filter.append("(lDAPDisplayName=").append(oclass).append(")");
        }

        filter.insert(0, "(&(|").append(")(objectClass=classSchema))");
        // -----------------------------------

        final LdapContext ctx = connection.getInitialContext();

        final Set<String> schemaNames = new HashSet<String>();

        // Issue http://code.google.com/p/connid/issues/detail?id=24
        schemaNames.add(conf.getUidAttribute());

        final String schemaConfigurationPath = "CN=Schema,CN=Configuration";

        for (String suffix : conf.getBaseContextsToSynchronize()) {
            try {
                final NamingEnumeration<SearchResult> oclasses = ctx.search(
                        schemaConfigurationPath + "," + suffix,
                        filter.toString(),
                        searchCtls);

                while (oclasses.hasMoreElements()) {
                    final SearchResult oclass = oclasses.next();
                    schemaNames.addAll(getObjectSchemaNames(oclass));
                }
            } catch (NamingException e) {
                LOG.error(e, "Error retrieving schema names from {0}", suffix);
            }
        }

        final ObjectClassInfoBuilder objClassBld = new ObjectClassInfoBuilder();

        // ObjectClass.ACCOUNT/ObjectClass.GROUP
        objClassBld.setType(ObjectClass.ACCOUNT_NAME);

        objClassBld.setContainer(false);

        objClassBld.addAllAttributeInfo(createAttrInfos(schemaNames));

        final ObjectClassInfo oci = objClassBld.build();
        schemaBld.defineObjectClass(oci);

        schema = schemaBld.build();
    }

    private Set<String> getObjectSchemaNames(final SearchResult oclass)
            throws NamingException {

        final Set<String> schemaNames = new HashSet<String>();

        for (String attrName : ATTRIBUTES_TO_GET) {
            final Attribute attr = oclass.getAttributes().get(attrName);

            if (attr != null) {
                final NamingEnumeration en = attr.getAll();

                while (en.hasMoreElements()) {
                    final String elem = (String) en.nextElement();

                    if (StringUtil.isNotBlank(elem)) {
                        schemaNames.add(elem.trim());
                    }
                }
            }
        }

        return schemaNames;
    }

    private List<AttributeInfo> createAttrInfos(final Set<String> schemaNames) {

        final List<AttributeInfo> infos = new ArrayList<AttributeInfo>();

        for (String schemaName : schemaNames) {
            infos.add(handleAttribute(schemaName));
        }

        return infos;
    }

    private AttributeInfo handleAttribute(final String displayName) {
        final String IS_SINGLE_VALUE = "isSingleValued";
        final String SYSTEM_ONLY = "systemOnly";
        final String LDAP_DISPLAY_NAME = "lDAPDisplayName";

        final Set<Flags> flags = EnumSet.noneOf(Flags.class);

        boolean binary = connection.isBinarySyntax(displayName);

        boolean objectClass = displayName == null
                || "objectClass".equalsIgnoreCase(displayName);

        final LdapContext ctx = connection.getInitialContext();

        final String[] baseContexts =
                connection.getConfiguration().getBaseContextsToSynchronize();

        // ------------------------------
        // Search control
        // ------------------------------
        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningAttributes(
                new String[]{IS_SINGLE_VALUE, SYSTEM_ONLY});
        // ------------------------------

        int i = 0;
        Attributes attributes = null;

        while (attributes == null && i < baseContexts.length) {

            final StringBuilder dn = new StringBuilder();

            dn.append("cn=schema, cn=configuration,").append(baseContexts[i]);

            try {

                final NamingEnumeration<SearchResult> result = ctx.search(
                        dn.toString(),
                        LDAP_DISPLAY_NAME + "=" + displayName,
                        searchCtls);

                if (result != null && result.hasMoreElements()) {
                    attributes = result.next().getAttributes();
                }

            } catch (NamingException e) {
                LOG.error(e, "Error retrieving attributes for {0}", dn);
            }

            i++;
        }

        if (attributes != null) {
            final Attribute isSingle = attributes.get(IS_SINGLE_VALUE);

            try {
                if (isSingle == null
                        || isSingle.get() == null
                        || "false".equalsIgnoreCase(isSingle.get().toString())) {
                    flags.add(Flags.MULTIVALUED);
                }
            } catch (NamingException e) {
                LOG.error(e, "Failure retrieving attribute " + IS_SINGLE_VALUE);
            }

            final Attribute systemOnly = attributes.get(SYSTEM_ONLY);
            try {
                if ((systemOnly != null
                        && systemOnly.get() != null
                        && "true".equalsIgnoreCase(systemOnly.get().toString()))
                        || objectClass) {
                    flags.add(Flags.NOT_CREATABLE);
                    flags.add(Flags.NOT_UPDATEABLE);
                }
            } catch (NamingException e) {
                LOG.error(e, "Failure retrieving attribute " + SYSTEM_ONLY);
            }
        }

        return AttributeInfoBuilder.build(
                displayName,
                binary ? byte[].class : String.class,
                flags);
    }
}
