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

import org.connid.ad.sync.ADSyncStrategy;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
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
    private transient ADSyncStrategy syncStrategy;

    /**
     * The connection to the AD server.
     */
    private transient ADConnection conn;

    @Override
    public Configuration getConfiguration() {
        return config;
    }

    @Override
    public void init(final Configuration cfg) {

        config = (ADConfiguration) cfg;
        // TODO: easier and more efficient if conn was protected in superclass
        conn = new ADConnection(config);

        syncStrategy = new ADSyncStrategy(conn);
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
