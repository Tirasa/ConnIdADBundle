package org.connid.ad.sync;

import com.sun.jndi.ldap.ctl.DirSyncControl;
import com.sun.jndi.ldap.ctl.DirSyncResponseControl;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import org.identityconnectors.common.CollectionUtil;
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
public class DirSyncSyncStrategy {

    private static final Log LOG = Log.getLog(DirSyncSyncStrategy.class);

    private static final String USERACCOUNTCONTROL_ATTR = "userAccountControl";

    private final transient LdapConnection conn;

    private final transient GroupHelper groupHelper;

    private transient SyncToken latestSyncToken;

    public DirSyncSyncStrategy(final LdapConnection conn) {

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

    private ConnectorObject createConnectorObject(final String baseDN,
            final SearchResult result, final Set<String> attrsToGet,
            final boolean emptyAttrWhenNotFound, final ObjectClass oclass) {

        final LdapEntry entry = LdapEntry.create(baseDN, result);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);
        builder.setUid(conn.getSchemaMapping().createUid(oclass, entry));
        builder.setName(conn.getSchemaMapping().createName(oclass, entry));

        Attribute attribute;
        List<String> ldapGroups;
        Set<String> posixRefAttrs;
        List<String> posixGroups;

        final GuardedString emptyGS = new GuardedString();
        for (String attrName : attrsToGet) {
            attribute = null;
            if (LdapConstants.isLdapGroups(attrName)) {
                ldapGroups =
                        groupHelper.getLdapGroups(entry.getDN().toString());
                attribute = AttributeBuilder.build(
                        LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attrName)) {
                posixRefAttrs =
                        LdapUtil.getStringAttrValues(entry.getAttributes(),
                        GroupHelper.getPosixRefAttribute());
                posixGroups = groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(
                        LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attrName)) {
                attribute = AttributeBuilder.build(attrName, emptyGS);
            } else if (USERACCOUNTCONTROL_ATTR.equals(attrName)) {
                try {
                    LOG.ok("User Account Control: "
                            + result.getAttributes().
                            get(USERACCOUNTCONTROL_ATTR).get().toString());

                    if (result.getAttributes().
                            get(USERACCOUNTCONTROL_ATTR).get().equals("512")) {
                        attribute = AttributeBuilder.buildEnabled(true);
                    }

                    if (result.getAttributes().
                            get(USERACCOUNTCONTROL_ATTR).get().equals("514")) {
                        attribute = AttributeBuilder.buildEnabled(false);
                    }


                } catch (NamingException e) {
                    LOG.error(e, "While fetching " + USERACCOUNTCONTROL_ATTR);
                }
            } else {
                attribute = conn.getSchemaMapping().createAttribute(oclass,
                        attrName, entry, emptyAttrWhenNotFound);
            }
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
                    LOG.ok("Search found " + result.get(baseContextDn).size()
                            + " items");
                }

                if (updateLastSyncToken) {
                    rspCtls = ctx.getResponseControls();
                    if (rspCtls != null) {
                        if (LOG.isOk()) {
                            LOG.ok("Response Controls: " + rspCtls.length);
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
                            LOG.ok("Latest sync token set to "
                                    + latestSyncToken);
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

    /**
     * At the moment this is useless: the sAMAccountName should go here, while
     * the CN is used: why, Active Directory???
     * @param sr
     * @return
     * @throws NamingException 
     */
    private String getDeletedUserName(final SearchResult sr)
            throws NamingException {

        final String name = (String) sr.getAttributes().get("name").get();

        return name.substring(0, name.indexOf('\n'));
    }

    public void sync(final SyncToken token, final SyncResultsHandler handler,
            final OperationOptions options, final ObjectClass oclass) {

        final Set<String> attributesToGet =
                getAttributesToGet(options.getAttributesToGet(), oclass);
        if (LOG.isOk()) {
            LOG.ok("Returning attributes: " + attributesToGet);
        }

        final Set<String> jndiRetAttrs = new HashSet<String>(
                attributesToGet.size());
        for (String attrName : attributesToGet) {
            if (Name.NAME.equals(attrName)) {
                jndiRetAttrs.addAll(Arrays.asList(conn.getConfiguration().
                        getAccountUserNameAttributes()));
            } else if (Uid.NAME.equals(attrName)) {
                jndiRetAttrs.add(conn.getConfiguration().getUidAttribute());
            } else {
                jndiRetAttrs.add(attrName);
            }
        }
        if (LOG.isOk()) {
            LOG.ok("Returning attributes via JNDI: " + jndiRetAttrs);
        }

        final SearchControls searchCtls =
                LdapInternalSearch.createDefaultSearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setReturningAttributes(jndiRetAttrs.toArray(
                new String[jndiRetAttrs.size()]));

        final StringBuilder filter = new StringBuilder();
        final StringBuilder delfilter = new StringBuilder();
        filter.append("(&");
        delfilter.append("(&");
        delfilter.append("(isDeleted=TRUE)");
        for (String accountObjectClass :
                conn.getConfiguration().getAccountObjectClasses()) {

            filter.append("(objectClass=");
            delfilter.append("(objectClass=");
            filter.append(accountObjectClass);
            delfilter.append(accountObjectClass);
            filter.append(')');
            delfilter.append(')');
        }
        if (conn.getConfiguration().getAccountSearchFilter() != null && !conn.getConfiguration().getAccountSearchFilter().isEmpty()) {

            filter.append(conn.getConfiguration().getAccountSearchFilter());
        }
        filter.append(')');
        delfilter.append(')');
        if (LOG.isOk()) {
            LOG.ok("Search filter [updates]: " + filter.toString());
            LOG.ok("Search filter [Deletes]: " + delfilter.toString());
        }

        final LdapContext ctx = conn.getInitialContext();

        try {
            ctx.setRequestControls(null);
            if (token == null || !(token.getValue() instanceof byte[])
                    || ((byte[]) token.getValue()).length == 0) {

                LOG.ok("Requested synchronization with invalid token. "
                        + "Ignore it.");
                ctx.setRequestControls(new Control[]{new DirSyncControl()});
            } else {
                LOG.ok("Requested synchronization with valid token. "
                        + "Use it.");
                ctx.setRequestControls(new Control[]{new DirSyncControl(
                            1, Integer.MAX_VALUE, (byte[]) token.getValue(),
                            true)});
            }
        } catch (Exception e) {
            throw new ConnectorException(
                    "Could not set DirSync request controls", e);
        }

        final Map<String, Set<SearchResult>> updated =
                search(ctx, filter.toString(), searchCtls, true);

        searchCtls.setReturningAttributes(null);
        final Map<String, Set<SearchResult>> deleted =
                search(ctx, delfilter.toString(), searchCtls, false);

        searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE);
        searchCtls.setReturningAttributes(jndiRetAttrs.toArray(
                new String[jndiRetAttrs.size()]));
        NamingEnumeration<SearchResult> entryRead;
        SyncDeltaBuilder sdb;
        for (String baseContextDn :
                conn.getConfiguration().getBaseContextsToSynchronize()) {

            // 1. All "interesting" modified users for any given base context
            if (updated.containsKey(baseContextDn)) {
                for (SearchResult sr : updated.get(baseContextDn)) {
                    sdb = new SyncDeltaBuilder();
                    sdb.setToken(latestSyncToken);
                    sdb.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);

                    try {
                        ctx.setRequestControls(null);
                        entryRead = ctx.search(sr.getNameInNamespace(),
                                "(objectclass=*)", searchCtls);

                        sdb.setObject(createConnectorObject(baseContextDn,
                                entryRead.next(), attributesToGet,
                                options.getAttributesToGet() != null, oclass));
                    } catch (NamingException e) {
                        LOG.error(e, "While reading "
                                + sr.getNameInNamespace());

                        sdb.setObject(createConnectorObject(baseContextDn,
                                sr, attributesToGet,
                                options.getAttributesToGet() != null, oclass));
                    }

                    handler.handle(sdb.build());
                }
            }

            // 2. All deleted users
//            if (deleted.containsKey(baseContextDn)) {
//                for (SearchResult sr : deleted.get(baseContextDn)) {
//                    try {
//                        sdb = new SyncDeltaBuilder();
//                        sdb.setToken(latestSyncToken);
//                        sdb.setDeltaType(SyncDeltaType.DELETE);
//                        sdb.setUid(new Uid(getDeletedUserName(sr)));
//
//                        handler.handle(sdb.build());
//                    } catch (NamingException e) {
//                        LOG.error(e, "Could not fetch lastKnownParent");
//                    }
//                }
//            }
        }
    }

    public SyncToken getLatestSyncToken() {
        return latestSyncToken;
    }
}
