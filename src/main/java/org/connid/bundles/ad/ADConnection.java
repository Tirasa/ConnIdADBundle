/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.connid.bundles.ad;

import static org.connid.bundles.ldap.commons.LdapUtil.nullAsEmpty;
import static org.identityconnectors.common.StringUtil.isNotBlank;

import com.sun.jndi.ldap.ctl.PasswordExpiredResponseControl;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.connid.bundles.ad.schema.ADSchema;
import org.connid.bundles.ad.util.TrustAllSocketFactory;
import org.connid.bundles.ldap.LdapConnection;
import org.connid.bundles.ldap.LdapConnection.AuthenticationResult;
import org.connid.bundles.ldap.LdapConnection.AuthenticationResultType;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.GuardedString.Accessor;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

/**
 *
 * @author fabio
 */
public class ADConnection extends LdapConnection {

    private static final Log LOG = Log.getLog(ADConnection.class);

    private static final String LDAP_CTX_FACTORY =
            "com.sun.jndi.ldap.LdapCtxFactory";

    private static final String LDAP_CTX_SOCKET_FACTORY =
            "java.naming.ldap.factory.socket";

    private static final String LDAP_BINARY_ATTRIBUTE =
            "java.naming.ldap.attributes.binary";

    private LdapContext initCtx = null;

    private LdapContext syncCtx = null;

    private final ADSchema schema;

    private ADConfiguration config;

    public ADConnection(ADConfiguration config) {
        super(config);
        this.config = config;
        schema = new ADSchema(this);
    }

    @Override
    public AuthenticationResult authenticate(final String entryDN, final GuardedString password) {

        assert entryDN != null;

        if (LOG.isOk()) {
            LOG.ok("Attempting to authenticate {0}", entryDN);
        }

        final Pair<AuthenticationResult, LdapContext> pair = createContext(entryDN, password);

        if (pair.second != null) {
            quietClose(pair.second);
        }

        if (LOG.isOk()) {
            LOG.ok("Authentication result: {0}", pair.first);
        }

        return pair.first;
    }

    public ADSchema getADSchema() {
        return schema;
    }

    public LdapContext getSyncContext(final Control[] control) {
        return cloneContext(control);
    }

    @Override
    public void close() {
        try {
            super.close();
            quietClose(initCtx);
            quietClose(syncCtx);
        } finally {
            initCtx = null;
            syncCtx = null;
        }
    }

    private LdapContext cloneContext(final Control[] control) {
        LdapContext ctx = null;

        try {
            @SuppressWarnings({"UseOfObsoleteCollectionType", "rawtypes", "unchecked"})
            final Hashtable env = new Hashtable(getInitialContext().getEnvironment());

            ctx = new InitialLdapContext(env, null);
            ctx.setRequestControls(control);

        } catch (NamingException e) {
            LOG.error(e, "Context initialization failed");
        }

        return ctx;
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

    @Override
    public LdapContext getInitialContext() {
        if (this.initCtx != null) {
            return this.initCtx;
        }

        this.initCtx = connect(config.getPrincipal(), config.getCredentials());
        return initCtx;
    }

    private LdapContext connect(String principal, GuardedString credentials) {
        final Pair<AuthenticationResult, LdapContext> pair =
                createContext(principal, credentials);

        LOG.error("Authentication result {0}", pair.first.getType());

        if (pair.first.getType().equals(AuthenticationResultType.SUCCESS)) {
            return pair.second;
        }

        pair.first.propagate();
        throw new IllegalStateException("Should never get here");
    }

    private Pair<AuthenticationResult, LdapContext> createContext(
            final String principal, final GuardedString credentials) {

        final List<Pair<AuthenticationResult, LdapContext>> result =
                new ArrayList<Pair<AuthenticationResult, LdapContext>>(1);

        @SuppressWarnings("UseOfObsoleteCollectionType")
        final java.util.Hashtable<Object, Object> env = new java.util.Hashtable<Object, Object>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, getLdapUrls());
        env.put(Context.REFERRAL, "follow");

        if (config.isSsl()) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");

            if (config.isTrustAllCerts()) {
                env.put(LDAP_CTX_SOCKET_FACTORY, TrustAllSocketFactory.class.getName());
            }
        }

        // needs one env property more to retrieve binary objectGUID
        env.put(LDAP_BINARY_ATTRIBUTE, "objectGUID");

        String authentication = isNotBlank(principal) ? "simple" : "none";
        env.put(Context.SECURITY_AUTHENTICATION, authentication);

        if (LOG.isOk()) {
            LOG.ok("Initial context environment: {0}", env);
        }

        if (isNotBlank(principal)) {

            env.put(Context.SECURITY_PRINCIPAL, principal);

            if (credentials != null) {
                credentials.access(new Accessor() {

                    @Override
                    public void access(char[] clearChars) {
                        env.put(Context.SECURITY_CREDENTIALS, new String(clearChars));
                    }
                });
            }
        }

        result.add(createContext(env));

        return result.get(0);
    }

    private Pair<AuthenticationResult, LdapContext> createContext(
            @SuppressWarnings("UseOfObsoleteCollectionType")
            final java.util.Hashtable<?, ?> env) {

        AuthenticationResult authnResult = null;
        InitialLdapContext context = null;

        try {
            context = new InitialLdapContext(env, null);

            if (config.isRespectResourcePasswordPolicyChangeAfterReset()) {
                if (hasPasswordExpiredControl(context.getResponseControls())) {
                    authnResult = new AuthenticationResult(
                            AuthenticationResultType.PASSWORD_EXPIRED);
                }
            }

        } catch (AuthenticationException e) {
            // TODO: check AD response
            String message = e.getMessage().toLowerCase();
            if (message.contains("password expired")) { // Sun DS.
                authnResult = new AuthenticationResult(
                        AuthenticationResultType.PASSWORD_EXPIRED, e);
            } else if (message.contains("password has expired")) { // RACF.
                authnResult = new AuthenticationResult(
                        AuthenticationResultType.PASSWORD_EXPIRED, e);
            } else {
                authnResult = new AuthenticationResult(
                        AuthenticationResultType.FAILED, e);
            }

        } catch (NamingException e) {
            authnResult = new AuthenticationResult(
                    AuthenticationResultType.FAILED, e);
        }

        if (authnResult == null) {
            assert context != null;

            authnResult = new AuthenticationResult(
                    AuthenticationResultType.SUCCESS);
        }

        return new Pair<AuthenticationResult, LdapContext>(authnResult, context);
    }

    private static boolean hasPasswordExpiredControl(final Control[] controls) {
        if (controls != null) {
            for (Control control : controls) {
                if (control instanceof PasswordExpiredResponseControl) {
                    return true;
                }
            }
        }
        return false;
    }

    private String getLdapUrls() {
        final StringBuilder builder = new StringBuilder();

        builder.append("ldap://").
                append(config.getHost()).append(':').append(config.getPort());

        for (String failover : nullAsEmpty(config.getFailover())) {
            builder.append(' ');
            builder.append(failover);
        }

        return builder.toString();
    }

    @Override
    public void test() {
        checkAlive();
    }

    @Override
    public void checkAlive() {
        try {
            final Attributes attrs = getInitialContext().
                    getAttributes("", new String[]{"subschemaSubentry"});

            attrs.get("subschemaSubentry");
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }
}
