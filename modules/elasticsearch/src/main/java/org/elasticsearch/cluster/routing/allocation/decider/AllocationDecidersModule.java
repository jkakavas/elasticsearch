/*
 * Licensed to Elastic Search and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Elastic Search licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.cluster.routing.allocation.decider;

import org.elasticsearch.common.collect.Lists;
import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.inject.multibindings.Multibinder;
import org.elasticsearch.common.settings.Settings;

import java.util.List;

/**
 */
public class AllocationDecidersModule extends AbstractModule {

    private final Settings settings;

    private List<Class<? extends AllocationDecider>> allocations = Lists.newArrayList();

    public AllocationDecidersModule(Settings settings) {
        this.settings = settings;
    }

    @Override protected void configure() {
        Multibinder<AllocationDecider> allocationMultibinder = Multibinder.newSetBinder(binder(), AllocationDecider.class);
        allocationMultibinder.addBinding().to(SameShardAllocationDecider.class);
        allocationMultibinder.addBinding().to(FilterAllocationDecider.class);
        allocationMultibinder.addBinding().to(ReplicaAfterPrimaryActiveAllocationDecider.class);
        allocationMultibinder.addBinding().to(ThrottlingAllocationDecider.class);
        allocationMultibinder.addBinding().to(RebalanceOnlyWhenActiveAllocationDecider.class);
        allocationMultibinder.addBinding().to(ClusterRebalanceAllocationDecider.class);
        allocationMultibinder.addBinding().to(ConcurrentRebalanceAllocationDecider.class);
        allocationMultibinder.addBinding().to(AwarenessAllocationDecider.class);
        for (Class<? extends AllocationDecider> allocation : allocations) {
            allocationMultibinder.addBinding().to(allocation);
        }

        bind(AllocationDeciders.class).asEagerSingleton();
    }
}
