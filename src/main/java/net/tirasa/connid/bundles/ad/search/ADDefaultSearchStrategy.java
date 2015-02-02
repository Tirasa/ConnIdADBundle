/* 
 * Copyright 2015 ConnId.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.tirasa.connid.bundles.ad.search;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import net.tirasa.connid.bundles.ldap.search.DefaultSearchStrategy;
import net.tirasa.connid.bundles.ldap.search.SearchResultsHandler;
import org.identityconnectors.common.logging.Log;

public class ADDefaultSearchStrategy extends DefaultSearchStrategy {

    private static final Log LOG = Log.getLog(ADDefaultSearchStrategy.class);

    private final boolean ignoreNonExistingBaseDNs;

    static String searchControlsToString(SearchControls controls) {
        StringBuilder builder = new StringBuilder();
        builder.append("SearchControls: {returningAttributes=");
        String[] attrs = controls.getReturningAttributes();
        builder.append(attrs != null ? Arrays.asList(attrs) : "null");
        builder.append(", scope=");
        switch (controls.getSearchScope()) {
            case SearchControls.OBJECT_SCOPE:
                builder.append("OBJECT");
                break;
            case SearchControls.ONELEVEL_SCOPE:
                builder.append("ONELEVEL");
                break;
            case SearchControls.SUBTREE_SCOPE:
                builder.append("SUBTREE");
                break;
        }
        builder.append('}');
        return builder.toString();
    }

    public ADDefaultSearchStrategy(boolean ignoreNonExistingBaseDNs) {
        super(ignoreNonExistingBaseDNs);
        this.ignoreNonExistingBaseDNs = ignoreNonExistingBaseDNs;
    }

    @Override
    public void doSearch(
            final LdapContext initCtx,
            final List<String> baseDNs,
            final String query,
            final SearchControls searchControls,
            final SearchResultsHandler handler)
            throws NamingException {

        if (LOG.isOk()) {
            LOG.ok("Searching in {0} with filter {1} and {2}",
                    baseDNs, query, searchControlsToString(searchControls));
        }

        Iterator<String> baseDNIter = baseDNs.iterator();
        boolean proceed = true;

        while (baseDNIter.hasNext() && proceed) {
            String baseDN = baseDNIter.next();

            NamingEnumeration<SearchResult> results;
            try {
                results = initCtx.search(baseDN, query, searchControls);
            } catch (NameNotFoundException e) {
                if (!ignoreNonExistingBaseDNs) {
                    throw e;
                }
                LOG.warn(e, null);
                continue;
            } catch (InvalidNameException e) {
                if (!ignoreNonExistingBaseDNs) {
                    throw e;
                }
                LOG.warn(e, null);
                continue;
            }
            try {
                // hasMore call for referral resolution ... it fails with AD
                // while (proceed && results.hasMore()) {
                while (proceed && results.hasMoreElements()) {
                    proceed = handler.handle(baseDN, results.next());
                }
            } finally {
                results.close();
            }
        }
    }
}
