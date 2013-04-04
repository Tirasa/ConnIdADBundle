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
package org.connid.bundles.ad.search;

import static java.util.Collections.singletonList;
import static org.identityconnectors.common.StringUtil.isBlank;

import com.sun.jndi.ldap.ctl.VirtualListViewControl;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.PagedResultsControl;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.util.ADUtilities;
import org.connid.bundles.ldap.LdapConnection;
import org.connid.bundles.ldap.commons.LdapConstants;
import org.connid.bundles.ldap.search.LdapFilter;
import org.connid.bundles.ldap.search.LdapInternalSearch;
import org.connid.bundles.ldap.search.LdapSearchStrategy;
import org.connid.bundles.ldap.search.LdapSearches;
import org.connid.bundles.ldap.search.SearchResultsHandler;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;

public class ADSearch {

    private final LdapConnection conn;

    private final ObjectClass oclass;

    private final LdapFilter filter;

    private final OperationOptions options;

    private final String[] baseDNs;

    private final ADUtilities utils;

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

        this.utils = new ADUtilities((ADConnection) this.conn);
    }

    public ADSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final OperationOptions options) {

        this(conn, oclass, filter, options, oclass == ObjectClass.ACCOUNT
                ? conn.getConfiguration().getBaseContexts()
                : ((ADConfiguration) conn.getConfiguration()).getGroupBaseContexts());
    }

    public final void executeADQuery(final ResultsHandler handler) {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = utils.getAttributesToGet(attrsToGetOption, oclass);

        final LdapInternalSearch search = getInternalSearch(attrsToGet);

        search.execute(new SearchResultsHandler() {

            @Override
            public boolean handle(String baseDN, SearchResult result)
                    throws NamingException {
                return handler.handle(utils.createConnectorObject(
                        result.getNameInNamespace(),
                        result,
                        attrsToGet,
                        oclass));
            }
        });
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

        final String filterEntryDN = filter != null ? filter.getEntryDN() : null;
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

        final SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        final Set<String> ldapAttrsToGet = utils.getLdapAttributesToGet(attrsToGet, oclass);

        controls.setReturningAttributes(ldapAttrsToGet.toArray(new String[ldapAttrsToGet.size()]));
        controls.setSearchScope(searchScope);

        final String optionsFilter = LdapConstants.getSearchFilter(options);
        
        final String searchFilter = oclass.equals(ObjectClass.ACCOUNT)
                ? conn.getConfiguration().getAccountSearchFilter()
                : ((ADConfiguration) conn.getConfiguration()).getGroupSearchFilter();

        final String nativeFilter = filter != null ? filter.getNativeFilter() : null;
        
        return new LdapInternalSearch(
                conn,
                getSearchFilter(optionsFilter, nativeFilter, searchFilter),
                dns,
                strategy,
                controls);
    }

    private String getSearchFilter(String... optionalFilters) {
        final StringBuilder builder = new StringBuilder();
        final String ocFilter = getObjectClassFilter();
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
        if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
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

        if (scope == null) {
            if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
                scope = ((ADConfiguration) conn.getConfiguration()).getUserSearchScope();
            } else {
                scope = ((ADConfiguration) conn.getConfiguration()).getGroupSearchScope();
            }
        }

        if (OperationOptions.SCOPE_OBJECT.equals(scope)) {
            return SearchControls.OBJECT_SCOPE;
        } else if (OperationOptions.SCOPE_ONE_LEVEL.equals(scope)) {
            return SearchControls.ONELEVEL_SCOPE;
        } else if (OperationOptions.SCOPE_SUBTREE.equals(scope) || scope == null) {
            return SearchControls.SUBTREE_SCOPE;
        } else {
            throw new IllegalArgumentException("Invalid search scope " + scope);
        }
    }
}
