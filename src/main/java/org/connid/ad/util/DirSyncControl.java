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
package org.connid.ad.util;

import com.sun.jndi.ldap.BasicControl;
import com.sun.jndi.ldap.BerEncoder;
import java.io.IOException;

public class DirSyncControl extends BasicControl {

    public static final String OID = "1.2.840.113556.1.4.841";

    private static final byte[] EMPTY_COOKIE = new byte[0];

    private static final long serialVersionUID = -930993758829518418L;

    /**
     * LDAP_DIRSYNC_INCREMENTAL_VALUES | LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER |
     * LDAP_DIRSYNC_OBJECT_SECURITY
     */
    private int flags = 0x80000801;

    public DirSyncControl()
            throws IOException {
        super(OID, true, null);
        super.value = setEncodedValue(Integer.MAX_VALUE, EMPTY_COOKIE);
    }

    public DirSyncControl(int flags) throws IOException {
        super(OID, true, null);
        this.flags = flags;
        super.value = setEncodedValue(Integer.MAX_VALUE, EMPTY_COOKIE);
    }

    public DirSyncControl(byte[] cookie)
            throws IOException {
        super(OID, true, cookie);
        super.value = setEncodedValue(Integer.MAX_VALUE, cookie);
    }

    public DirSyncControl(int maxAttrCount, boolean criticality, byte[] cookie)
            throws IOException {
        super(OID, criticality, cookie);
        super.value = setEncodedValue(maxAttrCount, cookie);
    }

    public DirSyncControl(int maxAttrCount, boolean criticality)
            throws IOException {
        super(OID, criticality, null);
        super.value = setEncodedValue(maxAttrCount, EMPTY_COOKIE);
    }

    private byte[] setEncodedValue(int maxAttrCount, byte[] cookie)
            throws IOException {

        BerEncoder ber = new BerEncoder(64);
        ber.beginSeq(48); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        ber.encodeInt(flags);
        ber.encodeInt(maxAttrCount);
        ber.encodeOctetString(cookie, 4); // (cookie, Ber.ASN_OCTET_STR);
        ber.endSeq();
        return ber.getTrimmedBuf();
    }
}
