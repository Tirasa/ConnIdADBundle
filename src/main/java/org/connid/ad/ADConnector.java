package org.connid.ad;

import org.connid.ad.sync.DirSyncSyncStrategy;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.ldap.LdapConnection;
import org.identityconnectors.ldap.LdapConnector;
import org.identityconnectors.ldap.search.LdapFilter;

/**
 * All-java, agent-less Active Directory connector, extending LDAP connector.
 * @see org.identityconnectors.ldap.LdapConnector
 */
@ConnectorClass(configurationClass = ADConfiguration.class,
displayNameKey = "ADConnector")
public class ADConnector extends LdapConnector {

    private static final Log LOG = Log.getLog(ADConnector.class);

    /**
     * The configuration for this connector instance.
     */
    private transient ADConfiguration config;

    /**
     * The relative DirSyncSyncStrategy instance which sync-related
     * operations are delegated to.
     */
    private transient DirSyncSyncStrategy syncStrategy;

    /**
     * The connection to the AD server.
     */
    private transient LdapConnection conn;

    @Override
    public Configuration getConfiguration() {
        return config;
    }

    @Override
    public void init(final Configuration cfg) {

        config = (ADConfiguration) cfg;
        // TODO: easier and more efficient if conn was protected in superclass
        conn = new LdapConnection(config);

        syncStrategy = new DirSyncSyncStrategy(conn);
        super.init(cfg);
    }

    @Override
    public void dispose() {
        conn.close();
        super.dispose();
    }

    @Override
    public void executeQuery(
            final ObjectClass oclass,
            final LdapFilter query,
            final ResultsHandler handler,
            final OperationOptions options) {
        new ADLdapSearch(conn, oclass, query, options).executeADQuery(handler);
    }

    @Override
    public SyncToken getLatestSyncToken(final ObjectClass oclass) {
        return syncStrategy.getLatestSyncToken();
    }

    @Override
    public void sync(final ObjectClass oclass, final SyncToken token,
            final SyncResultsHandler handler, final OperationOptions options) {

        syncStrategy.sync(token, handler, options, oclass);
    }
}
