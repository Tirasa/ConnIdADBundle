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
package net.tirasa.connid.bundles.ad.sync;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import net.tirasa.adsddl.ntsd.controls.ShowDeletedControl;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ad.util.ADUtilities;
import net.tirasa.connid.bundles.ldap.search.LdapInternalSearch;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;

/**
 * An implementation of the sync operation based on the DirSync protocol, for Active Directory.
 */
public class USNSyncStrategy extends ADSyncStrategy {

    private static final Log LOG = Log.getLog(USNSyncStrategy.class);

    private final transient ADConnection conn;

    private transient SyncToken latestSyncToken;

    private final ADUtilities utils;

    public USNSyncStrategy(final ADConnection conn) {
        super(conn);
        this.conn = conn;
        this.utils = new ADUtilities(conn);
    }

    protected Set<SearchResult> searchForDeletedObjects(
            final LdapContext ctx,
            final String filter,
            final SearchControls searchCtls) throws NamingException {

        final Set<SearchResult> result = new HashSet<>();

        Set<String> namingContexts = getNamingContexts(ctx);

        if (namingContexts.isEmpty()) {
            LOG.warn("No root context found about {0}",
                    Arrays.asList(conn.getConfiguration().getBaseContextsToSynchronize()));
            return new HashSet<>();
        }

        String baseContextDn = namingContexts.iterator().next();

        if (LOG.isOk()) {
            LOG.ok("Searching from " + baseContextDn);
        }

        try {
            final NamingEnumeration<SearchResult> answer = ctx.search(baseContextDn, filter, searchCtls);

            while (answer.hasMoreElements()) {
                result.add(answer.nextElement());
            }
        } catch (NamingException e) {
            LOG.error(e, "While searching base context {0} with filter {1} and search controls {2}",
                    baseContextDn, filter, searchCtls);
        }

        return result;
    }

    @Override
    public void sync(
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {

        // get lastest sync token before start pulling objects
        getLatestSyncToken();

        if ((oclass.is(ObjectClass.ACCOUNT_NAME)
                && ((ADConfiguration) conn.getConfiguration()).isRetrieveDeletedUser())
                || (oclass.is(ObjectClass.GROUP_NAME)
                && ((ADConfiguration) conn.getConfiguration()).isRetrieveDeletedGroup())) {
            syncDeletedObjects(token, handler, options, oclass);
        }

        syncCurrentObjects(token, handler, options, oclass);
    }

    private void sync(
            final boolean deleted,
            final String givenFilter,
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {
        // -----------------------------------
        // Create basicLdapSearch control
        // -----------------------------------
        final SearchControls searchCtls = LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningAttributes(null);
        // -----------------------------------

        // -----------------------------------
        // Create basicLdapSearch filter
        // -----------------------------------
        final String filter;

        try {
            if (token == null
                    || token.getValue() == null
                    || !(token.getValue() instanceof String)
                    || token.getValue().toString().length() == 0) {

                if (LOG.isOk()) {
                    LOG.ok("Synchronization with empty token.");
                }

                filter = givenFilter;
            } else {
                if (LOG.isOk()) {
                    LOG.ok("Synchronization with token.");
                }

                filter = String.format("(&(uSNChanged>=%s)(%s))", token.getValue().toString(), givenFilter);
            }
        } catch (Exception e) {
            throw new ConnectorException("Could not set DirSync request controls", e);
        }

        if (LOG.isOk()) {
            LOG.ok("Search filter: " + filter);
        }
        // -----------------------------------

        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = utils.getAttributesToGet(attrsToGetOption, oclass);

        // -----------------------------------
        // Get Synchronization Context and perform
        // -----------------------------------
        try {
            LdapContext ctx = conn.getInitialContext().newInstance(new Control[] {
                new ShowDeletedControl()
            });

            final Set<SearchResult> changes = deleted
                    ? searchForDeletedObjects(ctx, filter, searchCtls)
                    : search(ctx, filter, searchCtls, false);

            int count = changes.size();
            if (LOG.isOk()) {
                LOG.ok("Found {0} changes", count);
            }

            if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
                for (SearchResult sr : changes) {
                    try {
                        handleSyncUDelta(
                                ctx,
                                sr,
                                attrsToGet,
                                count == 1 ? latestSyncToken : token,
                                handler);
                        count--;
                    } catch (NamingException e) {
                        LOG.error(e, "SyncDelta handling for '{0}' failed", sr.getName());
                    }
                }
            } else {
                for (SearchResult sr : changes) {
                    try {
                        handleSyncGDelta(
                                ctx,
                                sr,
                                attrsToGet,
                                count == 1 ? latestSyncToken : token,
                                handler);
                        count--;
                    } catch (NamingException e) {
                        LOG.error(e, "SyncDelta handling for '{0}' failed", sr.getName());
                    }
                }
            }
        } catch (NamingException e) {
            throw new ConnectorException("While looking for changes", e);
        }
        // -----------------------------------

        if (handler instanceof SyncTokenResultsHandler) {
            SyncTokenResultsHandler.class.cast(handler).handleResult(latestSyncToken);
        }
    }

    private void syncDeletedObjects(
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {

        // -----------------------------------
        // Create basicLdapSearch filter
        // -----------------------------------
        String filter = oclass.is(ObjectClass.ACCOUNT_NAME)
                ? // get user filter
                "(&(objectClass=user)(isDeleted=TRUE))"
                : // get group filter
                "(&(objectClass=group)(isDeleted=TRUE))";

        sync(true, filter, token, handler, options, oclass);
    }

    private void syncCurrentObjects(
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {

        // -----------------------------------
        // Create basicLdapSearch filter
        // -----------------------------------
        String filter = oclass.is(ObjectClass.ACCOUNT_NAME)
                ? // get user filter
                createDirSyncUFilter((ADConfiguration) conn.getConfiguration(), utils)
                : // get group filter
                createDirSyncGFilter();

        sync(false, filter, token, handler, options, oclass);
    }

    @Override
    public SyncToken getLatestSyncToken() {
        // -----------------------------------
        // Create basicLdapSearch control
        // -----------------------------------
        final SearchControls searchCtls = LdapInternalSearch.createDefaultSearchControls();
        searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE);
        searchCtls.setReturningAttributes(new String[] { "highestCommittedUSN" });
        // -----------------------------------

        final String filter = "(objectclass=*)";

        try {
            String highestCommittedUSN = getHighestCommittedUSN(conn.getInitialContext().newInstance(null));
            if (highestCommittedUSN != null) {
                latestSyncToken = new SyncToken(highestCommittedUSN);
            }

            if (LOG.isOk()) {
                LOG.ok("Latest sync token set to {0}", latestSyncToken);
            }
        } catch (NamingException e) {
            LOG.error(e,
                    "While searching for highestCommittedUSN with filter {1} and controls {2}", filter, searchCtls);
        }

        return latestSyncToken;
    }

    private String getHighestCommittedUSN(final LdapContext ctx) {
        try {
            DirContext dirContext = (DirContext) ctx.lookup("");
            Attributes attributes = dirContext.getAttributes("", new String[] { "highestCommittedUSN" });
            Attribute attribute = attributes.get("highestCommittedUSN");
            NamingEnumeration<?> all = attribute.getAll();
            while (all.hasMore()) {
                return (String) all.next();
            }
        } catch (NamingException e) {
            LOG.warn("While searching for highestCommittedUSN", e);
        }

        return null;
    }

    private Set<String> getNamingContexts(final LdapContext ctx) {
        Set<String> namingContexts = new HashSet<>();

        try {
            DirContext dirContext = (DirContext) ctx.lookup("");
            Attributes attributes = dirContext.getAttributes("", new String[] { "namingContexts" });
            Attribute attribute = attributes.get("namingContexts");
            NamingEnumeration<?> all = attribute.getAll();
            while (all.hasMore()) {
                String namingContext = (String) all.next();
                for (String baseContextDn : conn.getConfiguration().getBaseContextsToSynchronize()) {
                    if (baseContextDn.toLowerCase().endsWith(namingContext.toLowerCase())) {
                        namingContexts.add(namingContext);
                    }
                }
            }
        } catch (NamingException e) {
            LOG.warn("While searching for naming contexts", e);
        }

        return namingContexts;
    }

    @Override
    protected SyncDelta getSyncDelta(
            final ObjectClass oclass,
            final String entryDN,
            final SyncDeltaType syncDeltaType,
            final SyncToken token,
            final Attributes profile,
            final Collection<String> attrsToGet)
            throws NamingException {

        final SyncDeltaBuilder sdb = new SyncDeltaBuilder();

        // Set token
        sdb.setToken(token == null ? new SyncToken(StringUtil.EMPTY) : token);

        // Set Delta Type
        sdb.setDeltaType(syncDeltaType);

        javax.naming.directory.Attribute uidAttribute;

        Uid uid = null;

        if (StringUtil.isNotBlank(conn.getSchemaMapping().getLdapUidAttribute(oclass))) {
            uidAttribute = profile.get(conn.getSchemaMapping().getLdapUidAttribute(oclass));

            if (uidAttribute != null) {
                uid = new Uid(uidAttribute.get().toString());
            }
        }

        if (uid == null) {
            throw new ConnectorException("UID attribute not found");
        }

        // Set UID
        sdb.setUid(uid);

        // Set Connector Object
        sdb.setObject(utils.createConnectorObject(entryDN, profile, attrsToGet, oclass));

        return sdb.build();
    }

    private static String createDirSyncUFilter(final ADConfiguration conf, final ADUtilities utils) {
        StringBuilder filter = new StringBuilder();

        filter.append("(&(objectClass=user)").append(utils.getMembershipSearchFilter(conf)).
                append("(! (isDeleted=TRUE))").append(")");

        return filter.toString();
    }

    private static String createDirSyncGFilter() {
        return "(&(objectClass=group)(! (isDeleted=TRUE)))";
    }
}
