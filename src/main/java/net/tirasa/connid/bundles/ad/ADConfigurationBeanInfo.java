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

import java.beans.IntrospectionException;
import java.beans.PropertyDescriptor;
import java.beans.SimpleBeanInfo;
import java.util.ArrayList;
import java.util.List;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.AbstractConfiguration;

public class ADConfigurationBeanInfo extends SimpleBeanInfo {

    private static final Log LOG = Log.getLog(ADConfigurationBeanInfo.class);

    @Override
    public PropertyDescriptor[] getPropertyDescriptors() {
        final List<PropertyDescriptor> props = new ArrayList<>();
        try {
            /*
             * Connectivity
             */
            // ssl
            props.add(new PropertyDescriptor("ssl", LdapConfiguration.class));
            
            // trustAllCerts
            props.add(new PropertyDescriptor("trustAllCerts", ADConfiguration.class));

            // host
            props.add(new PropertyDescriptor("host", LdapConfiguration.class));

            // port
            props.add(new PropertyDescriptor("port", LdapConfiguration.class));

            // failover
            props.add(new PropertyDescriptor("failover", LdapConfiguration.class));
            
            // principal
            props.add(new PropertyDescriptor("principal", LdapConfiguration.class));

            // credentials
            props.add(new PropertyDescriptor("credentials", LdapConfiguration.class));

            // connectTimeout
            props.add(new PropertyDescriptor("connectTimeout", LdapConfiguration.class));

            // readTimeout
            props.add(new PropertyDescriptor("readTimeout", LdapConfiguration.class));

            /*
             * Identifying attributes
             */
            // uidAttribute
            props.add(new PropertyDescriptor("uidAttribute", LdapConfiguration.class));
            
            // gidAttribute
            props.add(new PropertyDescriptor("gidAttribute", LdapConfiguration.class));
            
            // aoidAttribute
            props.add(new PropertyDescriptor("aoidAttribute", LdapConfiguration.class));

            // defaultIdAttribute
            props.add(new PropertyDescriptor("defaultIdAttribute", ADConfiguration.class));
            
            // dnAttribute
            props.add(new PropertyDescriptor("dnAttribute", LdapConfiguration.class));

            // userAuthenticationAttributes
            props.add(new PropertyDescriptor("userAuthenticationAttributes", ADConfiguration.class));

            /*
             * Password attributes
             */
            // passwordAttribute
            props.add(new PropertyDescriptor("passwordAttribute", LdapConfiguration.class));

            // passwordAttributeToSynchronize
            props.add(new PropertyDescriptor("passwordAttributeToSynchronize", LdapConfiguration.class));

            // passwordDecryptionInitializationVector
            props.add(new PropertyDescriptor("passwordDecryptionInitializationVector", LdapConfiguration.class));

            // passwordDecryptionKey
            props.add(new PropertyDescriptor("passwordDecryptionKey", LdapConfiguration.class));

            // passwordHashAlgorithm
            props.add(new PropertyDescriptor("passwordHashAlgorithm", LdapConfiguration.class));
            
            // synchronizePasswords
            props.add(new PropertyDescriptor("synchronizePasswords", LdapConfiguration.class));

            // retrievePasswordsWithSearch
            props.add(new PropertyDescriptor("retrievePasswordsWithSearch", LdapConfiguration.class));

            // pwdUpdateOnly
            props.add(new PropertyDescriptor("pwdUpdateOnly", ADConfiguration.class));

            /*
            * Object classes
            */
            // accountObjectClasses
            props.add(new PropertyDescriptor("accountObjectClasses", LdapConfiguration.class));
            
            // groupObjectClasses
            props.add(new PropertyDescriptor("groupObjectClasses", LdapConfiguration.class));

            // anyObjectClasses
            props.add(new PropertyDescriptor("anyObjectClasses", LdapConfiguration.class));

            /*
            * Base contexts
            */
            // baseContexts
            props.add(new PropertyDescriptor("baseContexts", LdapConfiguration.class));

            // userBaseContexts
            props.add(new PropertyDescriptor("userBaseContexts", ADConfiguration.class));
            
            // groupBaseContexts
            props.add(new PropertyDescriptor("groupBaseContexts", ADConfiguration.class));
            
            // anyObjectBaseContexts
            props.add(new PropertyDescriptor("anyObjectBaseContexts", ADConfiguration.class));
            
            // defaultPeopleContainer
            props.add(new PropertyDescriptor("defaultPeopleContainer", ADConfiguration.class));
           
            // defaultGroupContainer
            props.add(new PropertyDescriptor("defaultGroupContainer", ADConfiguration.class));

            // defaultAnyObjectContainer
            props.add(new PropertyDescriptor("defaultAnyObjectContainer", ADConfiguration.class));
            
            /*
            * Group memberships & owners
            */
            // memberships
            props.add(new PropertyDescriptor("memberships", ADConfiguration.class));
            
            // membershipConservativePolicy
            props.add(new PropertyDescriptor("membershipConservativePolicy", ADConfiguration.class));
            
            // membershipsInOr
            props.add(new PropertyDescriptor("membershipsInOr", ADConfiguration.class));
            
            // groupOwnerReferenceAttribute
            props.add(new PropertyDescriptor("groupOwnerReferenceAttribute", ADConfiguration.class));
            
            // groupMemberAttribute
            props.add(new PropertyDescriptor("groupMemberAttribute", LdapConfiguration.class));
 
            // addPrincipalToNewGroups
            props.add(new PropertyDescriptor("addPrincipalToNewGroups", LdapConfiguration.class));

            /*
            * Search scopes
            */
            // userSearchScope
            props.add(new PropertyDescriptor("userSearchScope", LdapConfiguration.class));
            
            // groupSearchScope
            props.add(new PropertyDescriptor("groupSearchScope", LdapConfiguration.class));

            // anyObjectSearchScope
            props.add(new PropertyDescriptor("anyObjectSearchScope", LdapConfiguration.class));

            /*
            * Search filters
            */
            // accountSearchFilter
            props.add(new PropertyDescriptor("accountSearchFilter", LdapConfiguration.class));
            
            // groupSearchFilter
            props.add(new PropertyDescriptor("groupSearchFilter", LdapConfiguration.class));

            // anyObjectSearchFilter
            props.add(new PropertyDescriptor("anyObjectSearchFilter", LdapConfiguration.class));

            /*
             * VLV attributes
             */
            // useVlvControls
            props.add(new PropertyDescriptor("useVlvControls", LdapConfiguration.class));

            // vlvSortAttribute
            props.add(new PropertyDescriptor("vlvSortAttribute", LdapConfiguration.class));

            /*
            * Retrieve deleted
            */
            // retrieveDeletedUser
            props.add(new PropertyDescriptor("retrieveDeletedUser", ADConfiguration.class));
            
            // retrieveDeletedGroup
            props.add(new PropertyDescriptor("retrieveDeletedGroup", ADConfiguration.class));

            // retrieveDeletedAnyObject
            props.add(new PropertyDescriptor("retrieveDeletedAnyObject", ADConfiguration.class));

            /*
            * Syncs
            */
            // syncStrategy
            props.add(new PropertyDescriptor("syncStrategy", LdapConfiguration.class));
            
            // baseContextsToSynchronize
            props.add(new PropertyDescriptor("baseContextsToSynchronize", LdapConfiguration.class));
   
            // objectClassesToSynchronize
            props.add(new PropertyDescriptor("objectClassesToSynchronize", LdapConfiguration.class));
  
            // attributesToSynchronize
            props.add(new PropertyDescriptor("attributesToSynchronize", LdapConfiguration.class));

            // changeLogBlockSize
            props.add(new PropertyDescriptor("changeLogBlockSize", LdapConfiguration.class));

            // changeNumberAttribute
            props.add(new PropertyDescriptor("changeNumberAttribute", LdapConfiguration.class));

            // accountSynchronizationFilter
            props.add(new PropertyDescriptor("accountSynchronizationFilter", LdapConfiguration.class));

            /*
            * Misc
            */
            // _connectorMessages
            props.add(new PropertyDescriptor("connectorMessages", AbstractConfiguration.class));
            
            // excludeAttributeChangesOnUpdate
            props.add(new PropertyDescriptor("excludeAttributeChangesOnUpdate", ADConfiguration.class));

            // readSchema
            props.add(new PropertyDescriptor("readSchema", LdapConfiguration.class));
        } catch (IntrospectionException e) {
            LOG.error(e, "Failure retrieving properties");
            props.clear();
        }
        
        return props.toArray(new PropertyDescriptor[props.size()]);
    }
}
