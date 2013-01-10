package org.connid.bundles.ad;

import java.beans.IntrospectionException;
import java.beans.PropertyDescriptor;
import java.beans.SimpleBeanInfo;
import java.util.ArrayList;
import java.util.List;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.ldap.LdapConfiguration;

public class ADConfigurationBeanInfo extends SimpleBeanInfo {

    private static final Log LOG = Log.getLog(ADConfigurationBeanInfo.class);

    @Override
    public PropertyDescriptor[] getPropertyDescriptors() {
        final List<PropertyDescriptor> props =
                new ArrayList<PropertyDescriptor>();
        try {
            // host
            props.add(new PropertyDescriptor(
                    "host", LdapConfiguration.class));

            // port
            props.add(new PropertyDescriptor(
                    "port", LdapConfiguration.class));

            // principal
            props.add(new PropertyDescriptor(
                    "principal", LdapConfiguration.class));

            // credentials
            props.add(new PropertyDescriptor(
                    "credentials", LdapConfiguration.class));

            // trustAllCerts
            props.add(new PropertyDescriptor(
                    "trustAllCerts", ADConfiguration.class));

            // membershipsInOr
            props.add(new PropertyDescriptor(
                    "membershipsInOr", ADConfiguration.class));
            
            // loading
            props.add(new PropertyDescriptor(
                    "loading", ADConfiguration.class));

            // failover
            props.add(new PropertyDescriptor(
                    "failover", LdapConfiguration.class));

            // baseContextsToSynchronize
            props.add(new PropertyDescriptor(
                    "baseContextsToSynchronize", LdapConfiguration.class));

            // baseContexts
            props.add(new PropertyDescriptor(
                    "baseContexts", LdapConfiguration.class));
            
            // baseContexts
            props.add(new PropertyDescriptor(
                    "defaultPeopleContainer", ADConfiguration.class));

            // memberships
            props.add(new PropertyDescriptor(
                    "memberships", ADConfiguration.class));

            // accountSearchFilter
            props.add(new PropertyDescriptor(
                    "accountSearchFilter", LdapConfiguration.class));

            // retrieveDeletedUser
            props.add(new PropertyDescriptor(
                    "retrieveDeletedUser", ADConfiguration.class));

            // accountObjectClasses
            props.add(new PropertyDescriptor(
                    "accountObjectClasses", LdapConfiguration.class));

            // objectClassesToSynchronize
            props.add(new PropertyDescriptor(
                    "objectClassesToSynchronize", LdapConfiguration.class));

            // _connectorMessages
            props.add(new PropertyDescriptor(
                    "connectorMessages", AbstractConfiguration.class));

        } catch (IntrospectionException e) {
            LOG.error(e, "Failure retrieving properties");
            props.clear();
        }

        return props.toArray(new PropertyDescriptor[props.size()]);
    }
}
