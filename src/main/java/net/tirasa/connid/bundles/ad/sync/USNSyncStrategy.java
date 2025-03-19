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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
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
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;
import javax.naming.ldap.SortControl;
import net.tirasa.adsddl.ntsd.controls.ShowDeletedControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.connid.bundles.ad.ADConfiguration;
import net.tirasa.connid.bundles.ad.ADConnection;
import net.tirasa.connid.bundles.ad.ADConnector;
import net.tirasa.connid.bundles.ad.util.ADUtilities;
import net.tirasa.connid.bundles.ad.util.DeletedControl;
import net.tirasa.connid.bundles.ldap.search.LdapInternalSearch;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;

/**
 * An implementation of the sync operation based on the DirSync protocol, for Active Directory.
 */
public class USNSyncStrategy extends ADSyncStrategy {

    private static final Log LOG = Log.getLog(USNSyncStrategy.class);

    private static String USN = "uSNChanged";

    private String deleteTokenValue;

    private String createOrUpdateTokenValue;

    public USNSyncStrategy(final ADConnection conn) {
        super(conn);
    }

    protected List<SearchResult> search(
            final LdapContext ctx,
            final String filter,
            final SearchControls searchCtls,
            final byte[] cookie,
            final String baseContextDn) throws Exception {

        ctx.setRequestControls(new Control[] {
                new SortControl(USN, Control.CRITICAL),
                new PagedResultsControl(1000, cookie, Control.CRITICAL) });

        final List<SearchResult> result = new ArrayList<>();

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

    protected List<SearchResult> searchForDeletedObjects(
            final LdapContext ctx,
            final String filter,
            final SearchControls searchCtls) throws Exception {

        ctx.setRequestControls(new Control[] {
            new SortControl(USN, Control.CRITICAL),
            new ShowDeletedControl()
        });

        final List<SearchResult> result = new ArrayList<>();

        Set<String> namingContexts = getNamingContexts(ctx);

        if (namingContexts.isEmpty()) {
            LOG.warn("No root context found about {0}",
                    Arrays.asList(conn.getConfiguration().getBaseContextsToSynchronize()));
            return new ArrayList<>();
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
        latestSyncToken = token;

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
                    LOG.ok("Synchronization with token {0}", token.getValue());
                }

                String[] tokenValues = token.getValue().toString().split(",");
                deleteTokenValue = tokenValues[0];
                createOrUpdateTokenValue = tokenValues.length == 1 ? tokenValues[0] : tokenValues[1];

                filter = String.format("(&(!(%s<=%s))%s)",
                        USN,
                        deleted ? deleteTokenValue : createOrUpdateTokenValue,
                        givenFilter);
            }
        } catch (Exception e) {
            throw new ConnectorException("Could not set Sync request controls", e);
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
            LdapContext ctx = conn.getInitialContext().newInstance(new Control[] {});

            byte[] cookie = null;
            for (String baseContextDn : conn.getConfiguration().getBaseContextsToSynchronize()) {
                do {
                    final List<SearchResult> changes = deleted ?
                            searchForDeletedObjects(ctx, filter, searchCtls) :
                            search(ctx, filter, searchCtls, cookie, baseContextDn);

                    if (!deleted) {
                        cookie = getResponseCookie(ctx.getResponseControls());
                    }
                    int count = changes.size();
                    LOG.ok("Found {0} changes", count);

                    if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
                        for (SearchResult sr : changes) {
                            LOG.ok("Remaining {0} users to be processed", count);
                            try {
                                handleSyncUDelta(ctx, sr, attrsToGet, token, handler);
                                count--;
                            } catch (NamingException e) {
                                LOG.error(e, "SyncDelta handling for '{0}' failed", sr.getName());
                            }
                        }
                    } else {
                        for (SearchResult sr : changes) {
                            LOG.ok("Remaining {0} groups to be processed", count);
                            try {
                                handleSyncGDelta(ctx, sr, attrsToGet, token, handler);
                                count--;
                            } catch (NamingException e) {
                                LOG.error(e, "SyncDelta handling for '{0}' failed", sr.getName());
                            }
                        }
                    }
                } while (cookie != null);
            }
        } catch (Exception e) {
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
            final Collection<String> attrsToGet,
            final boolean effectiveDelete)
            throws NamingException {

        Attribute usn = profile.get(USN);
        if (usn != null) {
            if (effectiveDelete) {
                deleteTokenValue = usn.get().toString();
            } else {
                createOrUpdateTokenValue = usn.get().toString();
            }

            StringBuilder tokenBuilder = new StringBuilder();
            if (StringUtil.isNotBlank(deleteTokenValue)) {
                tokenBuilder.append(deleteTokenValue);
            }

            if (StringUtil.isNotBlank(createOrUpdateTokenValue)) {
                if (tokenBuilder.length() > 0) {
                    tokenBuilder.append(",");
                }
                tokenBuilder.append(createOrUpdateTokenValue);
            }

            latestSyncToken = new SyncToken(tokenBuilder.toString());
        }

        LOG.ok("Latest processing token {0}", latestSyncToken.getValue());
        return super.getSyncDelta(
                oclass, entryDN, syncDeltaType, latestSyncToken, profile, attrsToGet, effectiveDelete);
    }

    @Override
    protected void handleSyncGDelta(
            final LdapContext ctx,
            final SearchResult sr,
            final Collection<String> attrsToGet,
            final SyncToken token,
            final SyncResultsHandler handler)
            throws NamingException {

        if (ctx == null || sr == null) {
            throw new ConnectorException("Invalid context or search result.");
        }

        ctx.setRequestControls(new Control[] { new DeletedControl() });

        // Just used to retrieve object classes and to pass to getSyncDelta
        Attributes profile = sr.getAttributes();

        if (LOG.isOk()) {
            LOG.ok("Object profile: {0}", profile);
        }

        String guid = GUID.getGuidAsString((byte[]) profile.get(ADConnector.OBJECTGUID).get());

        boolean isDeleted = false;

        try {

            javax.naming.directory.Attribute attributeIsDeleted = profile.get("isDeleted");

            isDeleted = attributeIsDeleted != null
                    && attributeIsDeleted.get() != null
                    && Boolean.parseBoolean(
                            attributeIsDeleted.get().toString());

        } catch (NoSuchElementException e) {
            if (LOG.isOk()) {
                LOG.ok("Cannot find the isDeleted element for group.");
            }
        } catch (Throwable t) {
            LOG.error(t, "Error retrieving isDeleted attribute");
        }

        // We need for this beacause DirSync can return an uncomplete profile.
        profile = ctx.getAttributes("<GUID=" + guid + ">");

        final Attribute objectClasses = profile.get("objectClass");

        if (objectClasses.contains("group")) {
            final ADConfiguration conf = (ADConfiguration) conn.getConfiguration();

            if (LOG.isOk()) {
                LOG.ok("Created/Updated/Deleted group {0}", sr.getNameInNamespace());
            }

            if (isDeleted) {

                if (LOG.isOk()) {
                    LOG.ok("Deleted group {0}", sr.getNameInNamespace());
                }

                if (conf.isRetrieveDeletedGroup()) {
                    handler.handle(getSyncDelta(
                            ObjectClass.GROUP,
                            sr.getNameInNamespace(),
                            SyncDeltaType.DELETE,
                            token,
                            profile,
                            attrsToGet,
                            true));
                }

            } else {
                // user to be created/updated
                if (LOG.isOk()) {
                    LOG.ok("Created/Updated group {0}", sr.getNameInNamespace());
                }

                String userDN = sr.getNameInNamespace();

                handleEntry(
                        ctx, ObjectClass.GROUP, userDN, conf.getGroupSearchFilter(), handler, token, conf, attrsToGet);
            }
        } else {
            LOG.warn("Invalid object type {0}", objectClasses);
        }
    }

    private byte[] getResponseCookie(final Control[] controls) {
        if (controls != null) {
            for (Control control : controls) {
                if (control instanceof PagedResultsResponseControl) {
                    PagedResultsResponseControl pagedControl = (PagedResultsResponseControl) control;
                    return pagedControl.getCookie();
                }
            }
        }
        return null;
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
