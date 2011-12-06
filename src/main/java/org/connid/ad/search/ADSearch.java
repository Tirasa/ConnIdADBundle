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
package org.connid.ad.search;

import static org.connid.ad.ADConnector.*;

import static java.util.Collections.singletonList;
import static org.identityconnectors.common.CollectionUtil.newCaseInsensitiveSet;
import static org.identityconnectors.common.CollectionUtil.newSet;
import static org.identityconnectors.common.StringUtil.isBlank;

import com.sun.jndi.ldap.ctl.VirtualListViewControl;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.PagedResultsControl;
import org.connid.ad.ADConnection;
import org.connid.ad.util.ADUtilities;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapConnection;
import org.identityconnectors.ldap.LdapConstants;
import org.identityconnectors.ldap.LdapEntry;
import org.identityconnectors.ldap.schema.LdapSchemaMapping;
import org.identityconnectors.ldap.search.LdapFilter;
import org.identityconnectors.ldap.search.LdapInternalSearch;
import org.identityconnectors.ldap.search.LdapSearchStrategy;
import org.identityconnectors.ldap.search.LdapSearches;
import org.identityconnectors.ldap.search.SearchResultsHandler;

public class ADSearch {

    private final LdapConnection conn;

    private final ObjectClass oclass;

    private final LdapFilter filter;

    private final OperationOptions options;

    private final String[] baseDNs;

    private static final Log LOG = Log.getLog(ADSearch.class);

    public ADSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final OperationOptions options,
            final String[] baseDNs) {

        this.conn = conn;
        this.oclass = oclass;
        this.filter = filter;
        this.options = options;
        this.baseDNs = baseDNs;
    }

    public ADSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final OperationOptions options) {

        this(conn, oclass, filter, options,
                conn.getConfiguration().getBaseContexts());
    }

    public final void executeADQuery(final ResultsHandler handler) {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = getAttributesToGet(attrsToGetOption);

        LdapInternalSearch search = getInternalSearch(attrsToGet);

        final ADUtilities utils = new ADUtilities((ADConnection) conn);

        search.execute(new SearchResultsHandler() {

            @Override
            public boolean handle(String baseDN, SearchResult result)
                    throws NamingException {
                return handler.handle(utils.createConnectorObject(
                        result.getNameInNamespace(),
                        result.getAttributes(),
                        oclass));
            }
        });
    }

    private Set<String> getAttributesToGet(String[] attributesToGet) {
        Set<String> result;

        if (attributesToGet != null) {
            result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(attributesToGet));
            removeNonReadableAttributes(result);
            result.add(Name.NAME);
        } else {
            // This should include Name.NAME.
            result = getAttributesReturnedByDefault(conn, oclass);
        }

        // Uid is required to build a ConnectorObject.
        result.add(Uid.NAME);

        // AD specific, for checking wether a user is enabled or not
        result.add(UACCONTROL_ATTR);

        // Our password is marked as readable because of sync().
        // We really can't return it from search.
        if (result.contains(OperationalAttributes.PASSWORD_NAME)) {
            LOG.warn("Reading passwords not supported");
        }

        return result;
    }

    private LdapInternalSearch getInternalSearch(Set<String> attrsToGet) {
        // This is a bit tricky. If the LdapFilter has an entry DN,
        // we only need to look at that entry and check whether it matches
        // the native filter. Moreover, when looking at the entry DN
        // we must not throw exceptions if the entry DN does not exist or is
        // not valid -- just as no exceptions are thrown when the native
        // filter doesn't return any values.
        //
        // In the simple case when the LdapFilter has no entryDN, we
        // will just search over our base DNs looking for entries
        // matching the native filter.

        LdapSearchStrategy strategy;
        List<String> dns;
        int searchScope;

        String filterEntryDN = filter != null ? filter.getEntryDN() : null;
        if (filterEntryDN != null) {
            // Would be good to check that filterEntryDN is under the configured 
            // base contexts. However, the adapter is likely to pass entries
            // outside the base contexts, so not checking in order to be on the
            // safe side.
            strategy = new ADDefaultSearchStrategy(true);
            dns = singletonList(filterEntryDN);
            searchScope = SearchControls.OBJECT_SCOPE;
        } else {
            strategy = getSearchStrategy();
            dns = getBaseDNs();
            searchScope = getLdapSearchScope();
        }

        SearchControls controls =
                LdapInternalSearch.createDefaultSearchControls();
        Set<String> ldapAttrsToGet = getLdapAttributesToGet(attrsToGet);
        controls.setReturningAttributes(
                ldapAttrsToGet.toArray(new String[ldapAttrsToGet.size()]));
        controls.setSearchScope(searchScope);

        String optionsFilter = LdapConstants.getSearchFilter(options);
        String userFilter = null;
        if (oclass.equals(ObjectClass.ACCOUNT)) {
            userFilter = conn.getConfiguration().getAccountSearchFilter();
        }
        String nativeFilter = filter != null ? filter.getNativeFilter() : null;
        return new LdapInternalSearch(
                conn,
                getSearchFilter(optionsFilter, nativeFilter, userFilter),
                dns,
                strategy,
                controls);
    }

    private String getSearchFilter(String... optionalFilters) {
        StringBuilder builder = new StringBuilder();
        String ocFilter = getObjectClassFilter();
        int nonBlank = isBlank(ocFilter) ? 0 : 1;
        for (String optionalFilter : optionalFilters) {
            nonBlank += (isBlank(optionalFilter) ? 0 : 1);
        }
        if (nonBlank > 1) {
            builder.append("(&");
        }
        appendFilter(ocFilter, builder);
        for (String optionalFilter : optionalFilters) {
            appendFilter(optionalFilter, builder);
        }
        if (nonBlank > 1) {
            builder.append(')');
        }
        return builder.toString();
    }

    private LdapSearchStrategy getSearchStrategy() {
        LdapSearchStrategy strategy;
        if (ObjectClass.ACCOUNT.equals(oclass)) {
            // Only consider paged strategies for accounts,
            // just as the adapter does.

            boolean useBlocks = conn.getConfiguration().isUseBlocks();
            boolean usePagedResultsControl =
                    conn.getConfiguration().isUsePagedResultControl();
            int pageSize = conn.getConfiguration().getBlockSize();

            if (useBlocks && !usePagedResultsControl
                    && conn.supportsControl(VirtualListViewControl.OID)) {
                String vlvSortAttr =
                        conn.getConfiguration().getVlvSortAttribute();
                strategy = new ADVlvIndexSearchStrategy(vlvSortAttr, pageSize);
            } else if (useBlocks
                    && conn.supportsControl(PagedResultsControl.OID)) {
                strategy = new ADSimplePagedSearchStrategy(pageSize);
            } else {
                strategy = new ADDefaultSearchStrategy(false);
            }
        } else {
            strategy = new ADDefaultSearchStrategy(false);
        }
        return strategy;
    }

    private static void appendFilter(String filter, StringBuilder toBuilder) {
        if (!isBlank(filter)) {
            String trimmedUserFilter = filter.trim();
            boolean enclose = filter.charAt(0) != '(';
            if (enclose) {
                toBuilder.append('(');
            }
            toBuilder.append(trimmedUserFilter);
            if (enclose) {
                toBuilder.append(')');
            }
        }
    }

    private void removeNonReadableAttributes(Set<String> attributes) {
        // Since the groups attributes are fake attributes, we don't want to
        // send them to LdapSchemaMapping. This, for example, avoid an 
        // (unlikely) conflict with a custom attribute defined in the server
        // schema.
        boolean ldapGroups =
                attributes.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups =
                attributes.remove(LdapConstants.POSIX_GROUPS_NAME);
        conn.getSchemaMapping().removeNonReadableAttributes(oclass, attributes);
        if (ldapGroups) {
            attributes.add(LdapConstants.LDAP_GROUPS_NAME);
        }
        if (posixGroups) {
            attributes.add(LdapConstants.POSIX_GROUPS_NAME);
        }
    }

    private List<String> getBaseDNs() {
        List<String> result;
        QualifiedUid container = options.getContainer();
        if (container != null) {
            result = singletonList(LdapSearches.findEntryDN(
                    conn, container.getObjectClass(), container.getUid()));
        } else {
            result = Arrays.asList(baseDNs);
        }
        assert result != null;
        return result;
    }

    private String getObjectClassFilter() {
        StringBuilder builder = new StringBuilder();
        List<String> ldapClasses =
                conn.getSchemaMapping().getLdapClasses(oclass);
        boolean and = ldapClasses.size() > 1;
        if (and) {
            builder.append("(&");
        }
        for (String ldapClass : ldapClasses) {
            builder.append("(objectClass=");
            builder.append(ldapClass);
            builder.append(')');
        }
        if (and) {
            builder.append(')');
        }
        return builder.toString();
    }

    private int getLdapSearchScope() {
        String scope = options.getScope();
        if (OperationOptions.SCOPE_OBJECT.equals(scope)) {
            return SearchControls.OBJECT_SCOPE;
        } else if (OperationOptions.SCOPE_ONE_LEVEL.equals(scope)) {
            return SearchControls.ONELEVEL_SCOPE;
        } else if (OperationOptions.SCOPE_SUBTREE.equals(scope)
                || scope == null) {
            return SearchControls.SUBTREE_SCOPE;
        } else {
            throw new IllegalArgumentException("Invalid search scope " + scope);
        }
    }

    private Set<String> getLdapAttributesToGet(Set<String> attrsToGet) {
        Set<String> cleanAttrsToGet = newCaseInsensitiveSet();
        cleanAttrsToGet.addAll(attrsToGet);
        cleanAttrsToGet.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups =
                cleanAttrsToGet.remove(LdapConstants.POSIX_GROUPS_NAME);
        Set<String> result = conn.getSchemaMapping().getLdapAttributes(
                oclass, cleanAttrsToGet, true);
        if (posixGroups) {
            result.add(GroupHelper.getPosixRefAttribute());
        }
        // For compatibility with the adapter, we do not ask the server for DN
        // attributes, such as entryDN; we compute them ourselves. Some servers
        // might not support such attributes anyway.
        result.removeAll(LdapEntry.ENTRY_DN_ATTRS);
        return result;
    }

    public static Set<String> getAttributesReturnedByDefault(
            final LdapConnection conn, final ObjectClass oclass) {
        if (oclass.equals(LdapSchemaMapping.ANY_OBJECT_CLASS)) {
            return newSet(Name.NAME);
        }
        Set<String> result = newCaseInsensitiveSet();
        ObjectClassInfo oci = conn.getSchemaMapping().schema().
                findObjectClassInfo(oclass.getObjectClassValue());
        if (oci != null) {
            for (AttributeInfo info : oci.getAttributeInfo()) {
                if (info.isReturnedByDefault()) {
                    result.add(info.getName());
                }
            }
        }
        return result;
    }
}
