/**
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2011-2013 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License"). You may not use this file
 * except in compliance with the License.
 *
 * You can obtain a copy of the License at https://oss.oracle.com/licenses/CDDL
 * See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at https://oss.oracle.com/licenses/CDDL.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
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
