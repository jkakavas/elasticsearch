/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentAction;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentRequest;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentResponse;

public class TransportNodeEnrollmentAction extends HandledTransportAction<NodeEnrollmentRequest, NodeEnrollmentResponse> {


    @Inject
    public TransportNodeEnrollmentAction(TransportService transportService, ActionFilters actionFilters, SecurityContext context){
        super(NodeEnrollmentAction.NAME, transportService, actionFilters, NodeEnrollmentRequest::new);
    }


    @Override
    protected void doExecute(
        Task task, NodeEnrollmentRequest request, ActionListener<NodeEnrollmentResponse> listener) {

    }
}
