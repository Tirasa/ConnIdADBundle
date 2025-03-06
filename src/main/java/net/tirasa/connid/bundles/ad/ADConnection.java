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
package net.tirasa.connid.bundles.ad;

import static org.identityconnectors.common.StringUtil.isNotBlank;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsResponse;
import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;
import net.tirasa.connid.bundles.ad.schema.ADSchema;
import net.tirasa.connid.bundles.ad.util.TrustAllSocketFactory;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;

import org.identityconnectors.common.Pair;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;

public class ADConnection extends LdapConnection {

    private static final Log LOG = Log.getLog(ADConnection.class);

    private static final String LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    private static final String LDAP_CTX_SOCKET_FACTORY = "java.naming.ldap.factory.socket";

    private static final String LDAP_BINARY_ATTRIBUTE = "java.naming.ldap.attributes.binary";

    private LdapContext syncCtx = null;

    public ADConnection(LdapConfiguration config) {
        super(config);
        schema = new ADSchema(this);
    }

    public LdapContext getSyncContext(final Control[] control) {
        return cloneContext(control);
    }

    @Override
    public void close() {
        try {
            super.close();
            quietClose(new Pair<>(syncCtx, tlsCtx));
        } finally {
            syncCtx = null;
        }
    }

    private LdapContext cloneContext(final Control[] controls) {
        try {
            return getInitialContext().newInstance(controls);
        } catch (NamingException e) {
            LOG.error(e, "Context initialization failed");
            return null;
        }
    }

    @Override
    public LdapContext getInitialContext() {
        if (this.initCtx != null) {
            return this.initCtx;
        }

        Pair<LdapContext, StartTlsResponse> connectPair = connect(config.getPrincipal(), config.getCredentials());
        initCtx = connectPair.first;
        tlsCtx = connectPair.second;

        try {
            initCtx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });
        } catch (NamingException e) {
            LOG.error(e, "Error initializing request controls");
        }

        return initCtx;
    }

    @Override
    protected Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>> createContext(
            final String principal, final GuardedString credentials) {

        final List<Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>>> result =
                new ArrayList<Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>>>(1);

        @SuppressWarnings("UseOfObsoleteCollectionType")
        final Hashtable<Object, Object> env = new Hashtable<>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, getLdapUrls());
        env.put(Context.REFERRAL, "follow");
        env.put(LdapConstants.CONNECT_TIMEOUT_ENV_PROP, Long.toString(config.getConnectTimeout()));
        env.put(LdapConstants.READ_TIMEOUT_ENV_PROP, Long.toString(config.getReadTimeout()));

        if (config.isSsl()) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");

            if (((ADConfiguration) config).isTrustAllCerts()) {
                env.put(LDAP_CTX_SOCKET_FACTORY, TrustAllSocketFactory.class.getName());
            }
        }

        // needs one env property more to retrieve binary objectGUID and ntSecurityDescriptor
        env.put(LDAP_BINARY_ATTRIBUTE,
                ADConnector.SDDL_ATTR + " " + ADConnector.OBJECTGUID + " " + ADConnector.OBJECTSID);

        String authentication = isNotBlank(principal) ? "simple" : "none";
        env.put(Context.SECURITY_AUTHENTICATION, authentication);

        if (LOG.isOk()) {
            LOG.ok("Initial context environment: {0}", env);
        }

        if (isNotBlank(principal)) {

            env.put(Context.SECURITY_PRINCIPAL, principal);

            if (credentials != null) {
                credentials.access(clearChars -> {
                    if (clearChars == null || clearChars.length == 0) {
                        throw new InvalidCredentialException("Password is blank");
                    }
                    env.put(Context.SECURITY_CREDENTIALS, new String(clearChars));
                });
            }
        }

        result.add(createContext(env));

        return result.get(0);
    }
}
