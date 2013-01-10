package org.connid.bundles.ad.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.identityconnectors.common.logging.Log;

public class TrustAllSocketFactory extends SSLSocketFactory {

    private static final Log LOG = Log.getLog(TrustAllSocketFactory.class);

    private SSLSocketFactory socketFactory;

    public TrustAllSocketFactory() {
        try {
            final SSLContext ctx = SSLContext.getInstance("TLS");

            ctx.init(
                    null,
                    new TrustManager[]{new TrustAllTrustManager()},
                    new SecureRandom());

            socketFactory = ctx.getSocketFactory();
        } catch (Exception e) {
            LOG.error(e, "Error initializing SSL context");
        }
    }

    public static SocketFactory getDefault() {
        return new TrustAllSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return socketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return socketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(
            final Socket socket, final String string, final int i, final boolean bln)
            throws IOException {
        return socketFactory.createSocket(socket, string, i, bln);
    }

    @Override
    public Socket createSocket(final String string, final int i)
            throws IOException, UnknownHostException {
        return socketFactory.createSocket(string, i);
    }

    @Override
    public Socket createSocket(
            final String string, final int i, final InetAddress ia, final int i1)
            throws IOException, UnknownHostException {
        return socketFactory.createSocket(string, i, ia, i1);
    }

    @Override
    public Socket createSocket(final InetAddress ia, final int i)
            throws IOException {
        return socketFactory.createSocket(ia, i);
    }

    @Override
    public Socket createSocket(
            final InetAddress ia, final int i, final InetAddress ia1, final int i1)
            throws IOException {
        return socketFactory.createSocket(ia, i, ia1, i1);
    }
}
