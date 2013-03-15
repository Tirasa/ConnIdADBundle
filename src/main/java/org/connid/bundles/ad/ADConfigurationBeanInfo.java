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
package org.connid.bundles.ad;

import java.beans.IntrospectionException;
import java.beans.PropertyDescriptor;
import java.beans.SimpleBeanInfo;
import java.util.ArrayList;
import java.util.List;
import org.connid.bundles.ldap.LdapConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.AbstractConfiguration;

public class ADConfigurationBeanInfo extends SimpleBeanInfo {

    private static final Log LOG = Log.getLog(ADConfigurationBeanInfo.class);

    @Override
    public PropertyDescriptor[] getPropertyDescriptors() {
        final List<PropertyDescriptor> props =
                new ArrayList<PropertyDescriptor>();
        try {
            // host
            props.add(new PropertyDescriptor("host", LdapConfiguration.class));

            // port
            props.add(new PropertyDescriptor("port", LdapConfiguration.class));

            // principal
            props.add(new PropertyDescriptor("principal", LdapConfiguration.class));

            // credentials
            props.add(new PropertyDescriptor("credentials", LdapConfiguration.class));

            // trustAllCerts
            props.add(new PropertyDescriptor("trustAllCerts", ADConfiguration.class));

            // membershipsInOr
            props.add(new PropertyDescriptor("membershipsInOr", ADConfiguration.class));

            // loading
            props.add(new PropertyDescriptor("loading", ADConfiguration.class));

            // failover
            props.add(new PropertyDescriptor("failover", LdapConfiguration.class));

            // baseContextsToSynchronize
            props.add(new PropertyDescriptor("baseContextsToSynchronize", LdapConfiguration.class));

            // baseContexts
            props.add(new PropertyDescriptor("baseContexts", LdapConfiguration.class));

            // baseContexts
            props.add(new PropertyDescriptor("defaultPeopleContainer", ADConfiguration.class));

            // memberships
            props.add(new PropertyDescriptor("memberships", ADConfiguration.class));

            // accountSearchFilter
            props.add(new PropertyDescriptor("accountSearchFilter", LdapConfiguration.class));

            // retrieveDeletedUser
            props.add(new PropertyDescriptor("retrieveDeletedUser", ADConfiguration.class));

            // accountObjectClasses
            props.add(new PropertyDescriptor("accountObjectClasses", LdapConfiguration.class));

            // objectClassesToSynchronize
            props.add(new PropertyDescriptor("objectClassesToSynchronize", LdapConfiguration.class));

            // _connectorMessages
            props.add(new PropertyDescriptor("connectorMessages", AbstractConfiguration.class));

            // startSyncFromToday
            props.add(new PropertyDescriptor("startSyncFromToday", ADConfiguration.class));
        } catch (IntrospectionException e) {
            LOG.error(e, "Failure retrieving properties");
            props.clear();
        }

        return props.toArray(new PropertyDescriptor[props.size()]);
    }
}
