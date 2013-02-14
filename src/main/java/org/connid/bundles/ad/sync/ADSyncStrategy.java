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
package org.connid.bundles.ad.sync;

import com.sun.jndi.ldap.ctl.DirSyncResponseControl;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import org.connid.bundles.ad.ADConfiguration;
import org.connid.bundles.ad.ADConnection;
import org.connid.bundles.ad.util.ADUtilities;
import org.connid.bundles.ad.util.DeletedControl;
import org.connid.bundles.ad.util.DirSyncControl;
import org.connid.bundles.ad.util.DirSyncUtils;
import org.connid.bundles.ldap.search.LdapInternalSearch;
import org.identityconnectors.common.CollectionUtil;
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

/**
 * An implementation of the sync operation based on the DirSync protocol, for Active Directory.
 */
public class ADSyncStrategy {

    private static final Log LOG = Log.getLog(ADSyncStrategy.class);

    private final transient ADConnection conn;

    private transient SyncToken latestSyncToken;

    public ADSyncStrategy(final ADConnection conn) {

        this.conn = conn;
    }

    private Map<String, Set<SearchResult>> search(
            final LdapContext ctx,
            final String filter,
            final SearchControls searchCtls,
            final boolean updateLastSyncToken) {

        final Map<String, Set<SearchResult>> result =
                new HashMap<String, Set<SearchResult>>();

        for (String baseContextDn :
                conn.getConfiguration().getBaseContextsToSynchronize()) {

            if (LOG.isOk()) {
                LOG.ok("Searching from " + baseContextDn);
            }

            if (!result.containsKey(baseContextDn)) {
                result.put(baseContextDn, new HashSet<SearchResult>());
            }

            try {
                final NamingEnumeration<SearchResult> answer =
                        ctx.search(baseContextDn, filter, searchCtls);

                while (answer.hasMoreElements()) {
                    result.get(baseContextDn).add(answer.nextElement());
                }

                if (LOG.isOk()) {
                    LOG.ok("Search found {0} items", result.get(baseContextDn).size());
                }

                if (updateLastSyncToken) {
                    final Control[] rspCtls = ctx.getResponseControls();

                    if (rspCtls != null) {
                        if (LOG.isOk()) {
                            LOG.ok("Response Controls: {0}", rspCtls.length);
                        }

                        for (int i = 0; i < rspCtls.length; i++) {
                            if (rspCtls[i] instanceof DirSyncResponseControl) {
                                DirSyncResponseControl dirSyncRspCtl =
                                        (DirSyncResponseControl) rspCtls[i];
                                latestSyncToken =
                                        new SyncToken(dirSyncRspCtl.getCookie());
                            }
                        }

                        if (LOG.isOk()) {
                            LOG.ok("Latest sync token set to {0}",
                                    latestSyncToken);
                        }
                    }
                }
            } catch (NamingException e) {
                LOG.error(e, "While searching base context {0} with filter {1} "
                        + "and search controls {2}",
                        baseContextDn, filter.toString(), searchCtls);
            }
        }

        return result;
    }

    public void sync(
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {

        // -----------------------------------
        // Create search control
        // -----------------------------------
        final SearchControls searchCtls = LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningAttributes(null);
        // -----------------------------------

        // -----------------------------------
        // Get Synchronization Context
        // -----------------------------------
        final LdapContext ctx;

        try {
            if (token == null
                    || token.getValue() == null
                    || !(token.getValue() instanceof byte[])
                    || ((byte[]) token.getValue()).length == 0) {

                if (LOG.isOk()) {
                    LOG.ok("Synchronization with empty token.");
                }

                ctx = conn.getSyncContext(new Control[]{new DirSyncControl()});

                if (((ADConfiguration) conn.getConfiguration()).isStartSyncFromToday()) {
                    search(ctx, "(cn=__CONNID-NORES__)", searchCtls, true);
                    return;
                }

            } else {
                if (LOG.isOk()) {
                    LOG.ok("Synchronization with token.");
                }

                ctx = conn.getSyncContext(new Control[]{new DirSyncControl((byte[]) token.getValue())});
            }
        } catch (Exception e) {
            throw new ConnectorException("Could not set DirSync request controls", e);
        }
        // -----------------------------------

        // -----------------------------------
        // Create search filter
        // -----------------------------------
        final String filter = DirSyncUtils.createDirSyncFilter((ADConfiguration) conn.getConfiguration());

        if (LOG.isOk()) {
            LOG.ok("Search filter: " + filter);
        }
        // -----------------------------------

        final Map<String, Set<SearchResult>> changes = search(ctx, filter, searchCtls, true);

        for (String baseDN : conn.getConfiguration().getBaseContextsToSynchronize()) {

            if (changes.containsKey(baseDN)) {
                for (SearchResult sr : changes.get(baseDN)) {
                    try {

                        handleSyncDelta(
                                oclass,
                                ctx,
                                sr,
                                handler);

                    } catch (NamingException e) {
                        LOG.error(e, "SyncDelta handling for '{0}' failed", sr.getName());
                    }
                }
            }
        }
    }

    public SyncToken getLatestSyncToken() {
        return latestSyncToken;
    }

    @SuppressWarnings("unchecked")
    private void handleSyncDelta(
            final ObjectClass oclass,
            final LdapContext ctx,
            final SearchResult result,
            final SyncResultsHandler handler)
            throws NamingException {

        if (ctx == null || result == null) {
            throw new ConnectorException("Invalid context or search result.");
        }

        ctx.setRequestControls(new Control[]{new DeletedControl()});

        // Just used to retrieve object classes and to pass to getSyncDelta
        Attributes profile = result.getAttributes();

        if (LOG.isOk()) {
            LOG.ok("Object profile: {0}", profile);
        }

        final Set<String> classes = CollectionUtil.newCaseInsensitiveSet();

        String guid = DirSyncUtils.getGuidAsString((byte[]) profile.get("objectGUID").get());

        boolean isDeleted = false;

        try {

            javax.naming.directory.Attribute attributeIsDeleted = profile.get("isDeleted");

            isDeleted =
                    attributeIsDeleted != null
                    && attributeIsDeleted.get() != null
                    && Boolean.parseBoolean(
                    attributeIsDeleted.get().toString());

        } catch (NoSuchElementException e) {
            if (LOG.isOk()) {
                LOG.ok("Cannot find the isDeleted element for user.");
            }
        } catch (Throwable t) {
            LOG.error(t, "Error retrieving isDeleted attribute");
        }

        // We need for this beacause DirSync can return an uncomplete profile.
        profile = ctx.getAttributes("<GUID=" + guid + ">");

        final NamingEnumeration<String> objectClasses = 
                (NamingEnumeration<String>) profile.get("objectClass").getAll();

        while (objectClasses.hasMoreElements()) {
            classes.add(objectClasses.next());
        }

        final ADConfiguration conf = (ADConfiguration) conn.getConfiguration();

        final javax.naming.directory.Attribute member11;
        final javax.naming.directory.Attribute member00;

        if (classes.contains("group")) {
            // search for users in adn users out

            if (LOG.isOk()) {
                LOG.ok("Modified group {0}", result.getNameInNamespace());
            }

            member11 = result.getAttributes().get("member;range=1-1");
            member00 = result.getAttributes().get("member;range=0-0");

            ctx.setRequestControls(null);

            String userDN;

            if (member11 != null && !conf.isLoading()) {
                if (LOG.isOk()) {
                    LOG.ok("Found users 'IN' ...");
                }

                // users to be created/updated
                final NamingEnumeration<String> userDNs = (NamingEnumeration<String>) member11.getAll();

                while (userDNs.hasMoreElements()) {
                    // for each new user "in" we must verify custom ldap filter
                    userDN = userDNs.next();

                    if (DirSyncUtils.verifyFilter(ctx, userDN, conf)) {

                        if (LOG.isOk()) {
                            LOG.ok("IN user {0}", userDN);
                        }

                        profile = ctx.getAttributes(userDN);

                        guid = DirSyncUtils.getGuidAsString((byte[]) profile.get("objectGUID").get());

                        handler.handle(getSyncDelta(
                                oclass,
                                userDN,
                                SyncDeltaType.CREATE_OR_UPDATE,
                                profile));
                    }
                }
            }

            if (member00 != null && conf.isRetrieveDeletedUser()) {
                // users to be removed
                if (LOG.isOk()) {
                    LOG.ok("Found users 'OUT' ...");
                }

                final NamingEnumeration<String> userDNs =
                        (NamingEnumeration<String>) member00.getAll();

                while (userDNs.hasMoreElements()) {
                    // for each user "out" we must verify custom ldap filter
                    userDN = userDNs.next();

                    profile = ctx.getAttributes(userDN);

                    guid = DirSyncUtils.getGuidAsString((byte[]) profile.get("objectGUID").get());

                    SyncDeltaType deltaType;

                    if (!DirSyncUtils.verifyFilter(ctx, userDN, conf)) {
                        if (LOG.isOk()) {
                            LOG.ok("OUT user {0} - delete", userDN);
                        }

                        deltaType = SyncDeltaType.DELETE;

                    } else {
                        // update user i order to update memberOf
                        // issue http://code.google.com/p/connid/issues/detail?id=25

                        if (LOG.isOk()) {
                            LOG.ok("OUT user {0} - update", userDN);
                        }

                        deltaType = SyncDeltaType.CREATE_OR_UPDATE;
                    }

                    handler.handle(getSyncDelta(
                            oclass,
                            userDN,
                            deltaType,
                            profile));
                }
            }
        } else if (classes.contains("user")) {
            if (LOG.isOk()) {
                LOG.ok("Created/Updated/Deleted user {0}",
                        result.getNameInNamespace());
            }

            if (isDeleted) {

                if (LOG.isOk()) {
                    LOG.ok("Deleted user {0}", result.getNameInNamespace());
                }

                handler.handle(getSyncDelta(
                        oclass,
                        result.getNameInNamespace(),
                        SyncDeltaType.DELETE,
                        profile));

            } else {
                // user to be created/updated
                if (LOG.isOk()) {
                    LOG.ok("Created/Updated user {0}", result.getNameInNamespace());
                }

                if (DirSyncUtils.verifyFilter(
                        ctx, result.getNameInNamespace(), conf)) {

                    if (LOG.isOk()) {
                        LOG.ok("Matched user {0}", result.getNameInNamespace());
                    }

                    handler.handle(getSyncDelta(
                            oclass,
                            result.getNameInNamespace(),
                            SyncDeltaType.CREATE_OR_UPDATE,
                            profile));

                } else {
                    if (LOG.isOk()) {
                        LOG.ok("Ignore changes about user {0}",
                                result.getNameInNamespace());
                    }
                }
            }
        } else {
            if (LOG.isInfo()) {
                LOG.info("Invalid object type {0}", classes);
            }
        }
    }

    private SyncDelta getSyncDelta(
            final ObjectClass oclass,
            final String entryDN,
            final SyncDeltaType syncDeltaType,
            final Attributes profile)
            throws NamingException {

        final SyncDeltaBuilder sdb = new SyncDeltaBuilder();

        // Set token
        sdb.setToken(latestSyncToken);

        // Set Delta Type
        sdb.setDeltaType(syncDeltaType);

        javax.naming.directory.Attribute uidAttribute;

        Uid uid = null;

        if (StringUtil.isNotBlank(conn.getConfiguration().getUidAttribute())) {
            uidAttribute = profile.get(conn.getConfiguration().getUidAttribute());

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
        if (SyncDeltaType.DELETE == syncDeltaType) {
            sdb.setObject(new ADUtilities((ADConnection) conn).createDeletedObject(entryDN, uid, profile, oclass));
        } else {
            sdb.setObject(new ADUtilities((ADConnection) conn).createConnectorObject(entryDN, profile, oclass));
        }

        return sdb.build();
    }
}
