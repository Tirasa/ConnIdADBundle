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
package net.tirasa.connid.bundles.ad.util;

import com.sun.jndi.ldap.BerEncoder;
import java.io.IOException;
import javax.naming.ldap.BasicControl;

public class DirSyncControl extends BasicControl {

    public static final String OID = "1.2.840.113556.1.4.841";

    private static final byte[] EMPTY_COOKIE = new byte[0];

    private static final long serialVersionUID = -930993758829518418L;

    /**
     * LDAP_DIRSYNC_INCREMENTAL_VALUES | LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER | LDAP_DIRSYNC_OBJECT_SECURITY
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

        final BerEncoder ber = new BerEncoder(64);
        ber.beginSeq(48); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        ber.encodeInt(flags);
        ber.encodeInt(maxAttrCount);
        ber.encodeOctetString(cookie, 4); // (cookie, Ber.ASN_OCTET_STR);
        ber.endSeq();
        return ber.getTrimmedBuf();
    }
}
