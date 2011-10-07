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
package org.connid.ad;

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
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.ldap.search.DefaultSearchStrategy;
import org.identityconnectors.ldap.search.SearchResultsHandler;

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
            final SearchResultsHandler handler) throws NamingException {
        LOG.ok("Searching in {0} with filter {1} and {2}",
                baseDNs, query, searchControlsToString(searchControls));

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
