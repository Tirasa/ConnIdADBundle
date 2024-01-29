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
package net.tirasa.connid.bundles.ad.search;

import net.tirasa.connid.bundles.ldap.search.VlvIndexSearchStrategy;
import org.identityconnectors.common.logging.Log;

public class ADVlvIndexSearchStrategy extends VlvIndexSearchStrategy {

    private static final Log LOG = Log.getLog(ADVlvIndexSearchStrategy.class);

    public ADVlvIndexSearchStrategy(String vlvSortAttr, int pageSize) {
        super(vlvSortAttr, pageSize);
    }
}
