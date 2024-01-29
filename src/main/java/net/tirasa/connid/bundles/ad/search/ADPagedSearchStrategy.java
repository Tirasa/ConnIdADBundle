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

import net.tirasa.connid.bundles.ldap.search.PagedSearchStrategy;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.SortKey;
import org.identityconnectors.framework.spi.SearchResultsHandler;

public class ADPagedSearchStrategy extends PagedSearchStrategy {

    private static final Log LOG = Log.getLog(ADPagedSearchStrategy.class);

    public ADPagedSearchStrategy(
            final int pageSize,
            final String pagedResultsCookie,
            final Integer pagedResultsOffset,
            final SearchResultsHandler searchResultHandler,
            final SortKey[] sortKeys) {
        super(pageSize, pagedResultsCookie, pagedResultsOffset, searchResultHandler, sortKeys);
    }
}
