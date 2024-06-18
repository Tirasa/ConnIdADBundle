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
package net.tirasa.connid.bundles.ad.search;

import com.sun.jndi.ldap.ctl.VirtualListViewControl;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.PagedResultsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ad.ADConnector;
import net.tirasa.connid.bundles.ad.util.ADUtilities;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import net.tirasa.connid.bundles.ldap.search.LdapFilter;
import net.tirasa.connid.bundles.ldap.search.LdapInternalSearch;
import net.tirasa.connid.bundles.ldap.search.LdapSearch;
import net.tirasa.connid.bundles.ldap.search.LdapSearchResultsHandler;
import net.tirasa.connid.bundles.ldap.search.LdapSearchStrategy;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.spi.SearchResultsHandler;

public class ADSearch extends LdapSearch {

    private final ADUtilities utils;

    private static final Log LOG = Log.getLog(ADSearch.class);

    public ADSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final ResultsHandler handler,
            final OperationOptions options,
            final String[] baseDNs) {
        super(conn, oclass, filter, handler, options, baseDNs);

        this.utils = new ADUtilities((ADConnection) this.conn);
    }

    public ADSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final ResultsHandler handler,
            final OperationOptions options) {

        this(conn, oclass, filter, handler, options,
                oclass.is(ObjectClass.ACCOUNT_NAME)
                ? ((ADConfiguration) conn.getConfiguration()).getUserBaseContexts()
                : oclass.is(ObjectClass.GROUP_NAME)
                ? ((ADConfiguration) conn.getConfiguration()).getGroupBaseContexts()
                : oclass.is(LdapSchema.ANY_OBJECT_NAME)
                ? ((ADConfiguration) conn.getConfiguration()).getAnyObjectBaseContexts()
                : ((ADConfiguration) conn.getConfiguration()).getBaseContexts());
    }

    @Override
    public final void execute() {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = utils.getAttributesToGet(attrsToGetOption, oclass);

        final LdapInternalSearch search = getInternalSearch(attrsToGet);

        search.execute(new LdapSearchResultsHandler() {

            @Override
            public boolean handle(final String baseDN, final SearchResult result)
                    throws NamingException {
                return handler.handle(utils.createConnectorObject(
                        result.getNameInNamespace(),
                        result,
                        attrsToGet,
                        oclass));
            }
        });
    }

    @Override
    protected LdapInternalSearch getInternalSearch(final Set<String> attrsToGet) {
        // This is a bit tricky. If the LdapFilter has an entry DN,
        // we only need to look at that entry and check whether it matches
        // the native filter. Moreover, when looking at the entry DN
        // we must not throw exceptions if the entry DN does not exist or is
        // not valid -- just as no exceptions are thrown when the native
        // filter doesn't return any values.
        //
        // In the simple case when the LdapFilter has no entryDN, we
        // will just basicLdapSearch over our base DNs looking for entries
        // matching the native filter.

        LdapSearchStrategy strategy;
        List<String> dns;
        int searchScope;
        boolean ignoreUserAnyObjectConfig = false;

        final String filterEntryDN = filter == null ? null : filter.getEntryDN();

        if (filterEntryDN == null) {
            strategy = getSearchStrategy();
            dns = getBaseDNs();
            if (options.getOptions().containsKey(OP_IGNORE_CUSTOM_ANY_OBJECT_CONFIG)) {
                ignoreUserAnyObjectConfig = (boolean) options.getOptions().get(OP_IGNORE_CUSTOM_ANY_OBJECT_CONFIG);
            }
            searchScope = getLdapSearchScope(ignoreUserAnyObjectConfig);
        } else {
            // Would be good to check that filterEntryDN is under the configured 
            // base contexts. However, the adapter is likely to pass entries
            // outside the base contexts, so not checking in order to be on the
            // safe side.
            strategy = conn.getConfiguration().newDefaultSearchStrategy(true);

            try {
                dns = buildBaseContextFilter(filterEntryDN);
            } catch (InvalidNameException e) {
                LOG.error(e, "Error building entry DN filter starting from '{0}'", filterEntryDN);
                dns = getBaseDNs();
            }

            searchScope = SearchControls.OBJECT_SCOPE;
        }

        final SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        final Set<String> ldapAttrsToGet = utils.getLdapAttributesToGet(attrsToGet, oclass);

        controls.setReturningAttributes(ldapAttrsToGet.toArray(new String[0]));
        controls.setSearchScope(searchScope);

        final String optionsFilter = LdapConstants.getSearchFilter(options);

        if (LOG.isOk()) {
            LOG.ok("Options filter: '{0}'", optionsFilter);
        }

        final String searchFilter = oclass.equals(ObjectClass.ACCOUNT)
                ? conn.getConfiguration().getAccountSearchFilter()
                : oclass.equals(ObjectClass.GROUP)
                ? conn.getConfiguration().getGroupSearchFilter()
                : (!ignoreUserAnyObjectConfig)
                ? conn.getConfiguration().getAnyObjectSearchFilter()
                : null;

        if (LOG.isOk()) {
            LOG.ok("Search filter: '{0}'", searchFilter);
        }

        final String nativeFilter = filter != null ? filter.getNativeFilter() : null;

        if (LOG.isOk()) {
            LOG.ok("Native filter: '{0}'", nativeFilter);
        }

        final String membershipSearchFilter = oclass.equals(ObjectClass.ACCOUNT)
                ? ADUtilities.getMembershipSearchFilter(((ADConfiguration) conn.getConfiguration()))
                : null;

        if (LOG.isOk()) {
            LOG.ok("Membership filter: '{0}'", membershipSearchFilter);
        }

        return new LdapInternalSearch(
                conn,
                getSearchFilter(optionsFilter, nativeFilter, searchFilter, membershipSearchFilter),
                dns,
                strategy,
                controls);
    }

    /**
     * Accept DNs filter provided by CN only or prefix only or full DN.
     *
     * @param filterEntryDN provided entry DN filter.
     * @return base context filter.
     */
    private List<String> buildBaseContextFilter(final String filterEntryDN) throws InvalidNameException {
        try {
            final LdapName prefix = new LdapName(filterEntryDN);
            return getBaseDNs().stream().anyMatch(bdn -> {
                try {
                    return prefix.startsWith(new LdapName(bdn));
                } catch (InvalidNameException e) {
                    return false;
                }
            }) ? Collections.<String>singletonList(prefix.toString()) : Collections.emptyList();
        } catch (InvalidNameException ine) {
            LOG.info(ine, "'{0}' is not am entry DN. Let's try derive it", filterEntryDN);
            final LdapName prefix = new LdapName(String.format("CN=%s", filterEntryDN));
            return getBaseDNs().stream().map(bdn -> {
                try {
                    return new LdapName(bdn).addAll(prefix).toString();
                } catch (InvalidNameException e) {
                    return bdn;
                }
            }).collect(Collectors.toList());
        }
    }

    @Override
    protected String getSearchFilter(final String... optionalFilters) {
        // replace any substring like as objectGUID=ba36c308-792a-45a9-b374-7f330e9742ab with the correct query
        final String res = super.getSearchFilter(optionalFilters);

        final String resToLowerCase = res.toLowerCase(); // required to be case-insensitive
        final String toBeFound = ADConnector.OBJECTGUID.toLowerCase();

        final StringBuilder bld = new StringBuilder();

        int from;
        int to = 0;

        do {
            from = resToLowerCase.indexOf(toBeFound, to);
            if (from >= 0) {
                from += 11;
                bld.append(res.substring(to, from));
                to += from + 36;
                bld.append(Hex.getEscaped(GUID.getGuidAsByteArray(res.substring(from, to))));
            } else {
                bld.append(res.substring(to, res.length()));
            }
        } while (from >= 0 && to < res.length());

        return bld.toString();
    }

    @Override
    protected LdapSearchStrategy getSearchStrategy() {
        final LdapSearchStrategy result;

        if (options.getPageSize() != null) {
            if (conn.getConfiguration().isUseVlvControls() && conn.supportsControl(VirtualListViewControl.OID)) {
                String vlvSortAttr = conn.getConfiguration().getVlvSortAttribute();
                result = new ADVlvIndexSearchStrategy(vlvSortAttr, options.getPageSize());
            } else if (conn.supportsControl(PagedResultsControl.OID)) {
                result = new ADPagedSearchStrategy(
                        options.getPageSize(),
                        options.getPagedResultsCookie(),
                        options.getPagedResultsOffset(),
                        handler instanceof SearchResultsHandler ? (SearchResultsHandler) handler : null,
                        options.getSortKeys()
                );
            } else {
                result = conn.getConfiguration().newDefaultSearchStrategy(true);
            }
        } else {
            result = conn.getConfiguration().newDefaultSearchStrategy(true);
        }
        return result;
    }
}
