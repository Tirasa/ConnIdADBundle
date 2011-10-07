/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.connid.ad;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.GuardedString.Accessor;
import org.identityconnectors.ldap.LdapConfiguration;
import org.identityconnectors.ldap.LdapConnection;

/**
 *
 * @author fabio
 */
public class ADConnection extends LdapConnection {

    private static final Log LOG = Log.getLog(ADConnection.class);

    private LdapContext ctx = null;

    public ADConnection(LdapConfiguration config) {
        super(config);
    }

    @Override
    public LdapContext getInitialContext() {
        if (ctx == null) {
            final LdapContext origCtx = super.getInitialContext();

            try {
                @SuppressWarnings("UseOfObsoleteCollectionType")
                final java.util.Hashtable env =
                        new java.util.Hashtable(origCtx.getEnvironment());

                // close previous initial context
                super.close();

                // needs one env property more to retrieve binary objectGUID
                env.put("java.naming.ldap.attributes.binary", "objectGUID");

                LOG.ok("Initial Ldap Context Environment: {0}", env);

                final GuardedString credentials =
                        getConfiguration().getCredentials();

                final String principal =
                        getConfiguration().getPrincipal();

                if (StringUtil.isNotBlank(principal) && credentials != null) {
                    env.put(Context.SECURITY_PRINCIPAL, principal);

                    credentials.access(new Accessor() {

                        @Override
                        public void access(char[] clearChars) {
                            LOG.ok("Clear Chars: {0}", new String(clearChars));
                            env.put(Context.SECURITY_CREDENTIALS, clearChars);
                            try {
                                ctx = new InitialLdapContext(env, null);
                            } catch (NamingException e) {
                                LOG.error(e, "Context initialization failed");
                                ctx = origCtx;
                            }
                        }
                    });
                } else {
                    LOG.ok("Credentials not found");
                    ctx = new InitialLdapContext(env, null);
                }

            } catch (NamingException e) {
                LOG.error(e, "Context initialization failed");
                ctx = origCtx;
            }
        }

        return ctx;
    }

    @Override
    public void close() {
        try {
            super.close();
            quietClose(ctx);
        } finally {
            ctx = null;
        }
    }

    private static void quietClose(final LdapContext ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException e) {
            LOG.warn(e, "Failure closing context");
        }
    }
}
