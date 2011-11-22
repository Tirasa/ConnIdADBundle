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
package org.connid.ad.sync;

import com.sun.jndi.ldap.ctl.DirSyncResponseControl;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
import org.connid.ad.util.DeletedControl;
import org.connid.ad.util.DirSyncControl;
import org.connid.ad.util.DirSyncUtils;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapConnection;
import org.identityconnectors.ldap.LdapConstants;
import org.identityconnectors.ldap.LdapEntry;
import org.identityconnectors.ldap.LdapUtil;
import org.identityconnectors.ldap.search.LdapInternalSearch;
import org.identityconnectors.ldap.search.LdapSearch;

/**
 * An implementation of the sync operation based on the DirSync protocol,
 * for Active Directory.
 */
public class ADSyncStrategy {

    private static final Log LOG = Log.getLog(ADSyncStrategy.class);

    private static final String USERACCOUNTCONTROL_ATTR = "userAccountControl";

    private final transient LdapConnection conn;

    private final transient GroupHelper groupHelper;

    private transient SyncToken latestSyncToken;

    public ADSyncStrategy(final LdapConnection conn) {

        this.conn = conn;
        this.groupHelper = new GroupHelper(conn);
    }

    private Set<String> getAttributesToGet(final String[] attributesToGet,
            final ObjectClass oclass) {

        Set<String> result;
        if (attributesToGet == null) {
            // This should include Name.NAME,
            // so no need to include it explicitly.
            result = LdapSearch.getAttributesReturnedByDefault(conn, oclass);
        } else {
            result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(attributesToGet));
            result.add(Name.NAME);
        }

        // Since Uid is not in the schema,
        // but it is required to construct a ConnectorObject.
        result.add(Uid.NAME);

        // Our password is marked as readable because of sync().
        // We really can't return it from search.
        if (result.contains(OperationalAttributes.PASSWORD_NAME)) {
            LOG.warn("Reading passwords not supported");
        }

        // AD specific, for checking wether a user is enabled or not
        result.add(USERACCOUNTCONTROL_ATTR);

        return result;
    }

    private ConnectorObject createConnectorObject(
            final String baseDN,
            final Attributes profile,
            final ObjectClass oclass)
            throws NamingException {

        final LdapEntry entry = LdapEntry.create(baseDN, profile);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);
        builder.setUid(conn.getSchemaMapping().createUid(oclass, entry));
        builder.setName(conn.getSchemaMapping().createName(oclass, entry));

        Attribute attribute;
        List<String> ldapGroups;
        Set<String> posixRefAttrs;
        List<String> posixGroups;

        final GuardedString emptyGS = new GuardedString();

        final NamingEnumeration<String> attributeNames = profile.getIDs();
        String attributeName;

        while (attributeNames.hasMoreElements()) {
            attributeName = attributeNames.next();

            attribute = null;

            if (LdapConstants.isLdapGroups(attributeName)) {
                ldapGroups =
                        groupHelper.getLdapGroups(entry.getDN().toString());
                attribute = AttributeBuilder.build(
                        LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attributeName)) {
                posixRefAttrs =
                        LdapUtil.getStringAttrValues(entry.getAttributes(),
                        GroupHelper.getPosixRefAttribute());
                posixGroups = groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(
                        LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attributeName)) {
                attribute = AttributeBuilder.build(attributeName, emptyGS);
            } else if (USERACCOUNTCONTROL_ATTR.equals(attributeName)) {
                try {
                    LOG.ok("User Account Control: {0}", profile.get(
                            USERACCOUNTCONTROL_ATTR).get().toString());

                    if (profile.get(USERACCOUNTCONTROL_ATTR).get().
                            equals("512")) {
                        attribute = AttributeBuilder.buildEnabled(true);
                    }

                    if (profile.get(USERACCOUNTCONTROL_ATTR).get().
                            equals("514")) {
                        attribute = AttributeBuilder.buildEnabled(false);
                    }


                } catch (NamingException e) {
                    LOG.error(e, "While fetching " + USERACCOUNTCONTROL_ATTR);
                }
            } else {
                attribute = conn.getSchemaMapping().createAttribute(
                        oclass, attributeName, entry, false);
            }

            // Avoid attribute adding in case of attribute name not found
            if (attribute != null) {
                builder.addAttribute(attribute);
            }
        }

        return builder.build();
    }

    private Map<String, Set<SearchResult>> search(final LdapContext ctx,
            final String filter, final SearchControls searchCtls,
            final boolean updateLastSyncToken) {

        final Map<String, Set<SearchResult>> result =
                new HashMap<String, Set<SearchResult>>();

        NamingEnumeration<SearchResult> answer;
        Control[] rspCtls;
        DirSyncResponseControl dirSyncRspCtl;
        for (String baseContextDn :
                conn.getConfiguration().getBaseContextsToSynchronize()) {

            if (LOG.isOk()) {
                LOG.ok("Searching from " + baseContextDn);
            }

            if (!result.containsKey(baseContextDn)) {
                result.put(baseContextDn, new HashSet<SearchResult>());
            }

            try {
                answer = ctx.search(baseContextDn, filter, searchCtls);
                while (answer.hasMoreElements()) {
                    result.get(baseContextDn).add(answer.nextElement());
                }
                if (LOG.isOk()) {
                    LOG.ok("Search found {0} items",
                            result.get(baseContextDn).size());
                }

                if (updateLastSyncToken) {
                    rspCtls = ctx.getResponseControls();
                    if (rspCtls != null) {
                        if (LOG.isOk()) {
                            LOG.ok("Response Controls: {0}", rspCtls.length);
                        }
                        for (int i = 0; i < rspCtls.length; i++) {
                            if (rspCtls[i] instanceof DirSyncResponseControl) {
                                dirSyncRspCtl =
                                        (DirSyncResponseControl) rspCtls[i];
                                latestSyncToken = new SyncToken(
                                        dirSyncRspCtl.getCookie());
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
        // Create search filter
        // -----------------------------------
        final String filter =
                DirSyncUtils.createLdapFilter(conn.getConfiguration());

        if (LOG.isOk()) {
            LOG.ok("Search filter: " + filter);
        }
        // -----------------------------------

        // -----------------------------------
        // Create search control
        // -----------------------------------
        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningAttributes(null);
        // -----------------------------------

        // -----------------------------------
        // Get Synchronization Context
        // -----------------------------------
        LdapContext ctx = conn.getInitialContext();

        try {
            if (token == null
                    || token.getValue() == null
                    || !(token.getValue() instanceof byte[])
                    || ((byte[]) token.getValue()).length == 0) {

                if (LOG.isOk()) {
                    LOG.ok("Synchronization with empty token.");
                }
                ctx.setRequestControls(new Control[]{new DirSyncControl()});
            } else {
                if (LOG.isOk()) {
                    LOG.ok("Synchronization with token.");
                }
                ctx.setRequestControls(new Control[]{
                            new DirSyncControl((byte[]) token.getValue())});
            }
        } catch (Exception e) {
            throw new ConnectorException(
                    "Could not set DirSync request controls", e);
        }
        // -----------------------------------

        final Map<String, Set<SearchResult>> changes =
                search(ctx, filter, searchCtls, true);

        final Set<String> handled = new HashSet<String>();

        for (String baseDN :
                conn.getConfiguration().getBaseContextsToSynchronize()) {

            if (changes.containsKey(baseDN)) {
                for (SearchResult sr : changes.get(baseDN)) {
                    try {
                        handleSyncDelta(
                                oclass, ctx, sr, baseDN, handler, handled);
                    } catch (NamingException e) {
                        LOG.error(e, "SyncDelta handling for '{0}' failed",
                                sr.getName());
                    }
                }
            }
        }
    }

    public SyncToken getLatestSyncToken() {
        return latestSyncToken;
    }

    private void handleSyncDelta(
            final ObjectClass oclass,
            final LdapContext ctx,
            final SearchResult sr,
            final String baseContext,
            final SyncResultsHandler handler,
            final Set<String> handled)
            throws NamingException {

        if (ctx == null || sr == null) {
            throw new ConnectorException("Invalid context or search result.");
        }

        ctx.setRequestControls(new Control[]{new DeletedControl()});

        // Just used to retrieve object classes and to pass to getSyncDelta
        Attributes profile = sr.getAttributes();

        if (LOG.isOk()) {
            LOG.ok("Object profile: {0}", profile);
        }

        final Set<String> classes = CollectionUtil.newCaseInsensitiveSet();

        String guid = DirSyncUtils.getGuidAsString(
                (byte[]) profile.get("objectGUID").get());

        if (handled.contains(guid)) {
            LOG.info("ObjectGUID {0} already handled", guid);
            return;
        }

        boolean isDeleted = false;

        try {

            javax.naming.directory.Attribute attributeIsDeleted =
                    profile.get("isDeleted");

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

        // We need for this beacause DirSync return an uncomplete profile
        // in case of entries updated or deleted.
        // We don't need to search for complete profile for new created users.
        if (profile.get("objectClass") == null || isDeleted) {
            profile = ctx.getAttributes("<GUID=" + guid + ">");
        }

        final NamingEnumeration<String> objectClasses =
                (NamingEnumeration<String>) profile.get("objectClass").getAll();

        while (objectClasses.hasMoreElements()) {
            classes.add(objectClasses.next());
        }

        final javax.naming.directory.Attribute member11;
        final javax.naming.directory.Attribute member00;

        if (classes.contains("group")) {
            // search for users in adn users out

            if (LOG.isOk()) {
                LOG.ok("Modified group {0}", sr.getNameInNamespace());
            }

            member11 = sr.getAttributes().get("member;range=1-1");
            member00 = sr.getAttributes().get("member;range=0-0");

            ctx.setRequestControls(null);
            String userDN;

            if (member11 != null) {
                if (LOG.isOk()) {
                    LOG.ok("Found users 'IN' ...");
                }

                // users to be created/updated
                final NamingEnumeration<String> userDNs =
                        (NamingEnumeration<String>) member11.getAll();

                while (userDNs.hasMoreElements()) {
                    // for each new user "in" we must verify custom ldap filter
                    userDN = userDNs.next();

                    if (DirSyncUtils.verifyFilter(
                            ctx, userDN, conn.getConfiguration())) {

                        if (LOG.isOk()) {
                            LOG.ok("IN user {0}", userDN);
                        }

                        profile = ctx.getAttributes(userDN);

                        guid = DirSyncUtils.getGuidAsString(
                                (byte[]) profile.get("objectGUID").get());

                        if (!handled.contains(guid)) {
                            handled.add(guid);

                            handler.handle(getSyncDelta(
                                    oclass,
                                    baseContext,
                                    SyncDeltaType.CREATE_OR_UPDATE,
                                    profile));
                        }
                    }
                }
            }

            if (member00 != null) {
                // users to be removed
                if (LOG.isOk()) {
                    LOG.ok("Found users 'OUT' ...");
                }

                final NamingEnumeration<String> userDNs =
                        (NamingEnumeration<String>) member00.getAll();

                while (userDNs.hasMoreElements()) {
                    userDN = userDNs.next();
                    if (LOG.isOk()) {
                        LOG.ok("OUT user {0}", userDN);
                    }

                    profile = ctx.getAttributes(userDN);

                    guid = DirSyncUtils.getGuidAsString(
                            (byte[]) profile.get("objectGUID").get());

                    if (!handled.contains(guid)) {
                        handled.add(guid);

                        handler.handle(getSyncDelta(
                                oclass,
                                baseContext,
                                SyncDeltaType.DELETE,
                                profile));
                    }
                }
            }
        } else if (classes.contains("user")) {
            if (LOG.isOk()) {
                LOG.ok("Created/Updated/Deleted user {0}",
                        sr.getNameInNamespace());
            }

            handled.add(guid);

            if (isDeleted) {

                if (LOG.isOk()) {
                    LOG.ok("Deleted user {0}", sr.getNameInNamespace());
                }

                handler.handle(getSyncDelta(
                        oclass,
                        baseContext,
                        SyncDeltaType.DELETE,
                        profile));
            } else {
                // user to be created/updated
                if (LOG.isOk()) {
                    LOG.ok("Created/Updated user {0}", sr.getNameInNamespace());
                }

                if (DirSyncUtils.verifyFilter(
                        ctx,
                        sr.getNameInNamespace(),
                        conn.getConfiguration())) {

                    if (LOG.isOk()) {
                        LOG.ok("Matched user {0}", sr.getNameInNamespace());
                    }

                    handler.handle(getSyncDelta(
                            oclass,
                            baseContext,
                            SyncDeltaType.CREATE_OR_UPDATE,
                            profile));
                } else {
                    if (LOG.isOk()) {
                        LOG.ok("Ignore changes about user {0}",
                                sr.getNameInNamespace());
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
            final String baseContextDn,
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
            uidAttribute =
                    profile.get(conn.getConfiguration().getUidAttribute());

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
        if (SyncDeltaType.DELETE != syncDeltaType) {
            sdb.setObject(createConnectorObject(baseContextDn, profile, oclass));
        }

        return sdb.build();
    }
}
