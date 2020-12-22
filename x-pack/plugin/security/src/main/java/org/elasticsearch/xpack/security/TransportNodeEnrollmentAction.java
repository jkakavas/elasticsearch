/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.env.Environment;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentAction;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentRequest;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentResponse;

import java.nio.file.Files;
import java.util.Base64;

public class TransportNodeEnrollmentAction extends HandledTransportAction<NodeEnrollmentRequest, NodeEnrollmentResponse> {
    final Environment environment;

    @Inject
    public TransportNodeEnrollmentAction(TransportService transportService, ActionFilters actionFilters, Environment environment,
        SecurityContext context){
        super(NodeEnrollmentAction.NAME, transportService, actionFilters, NodeEnrollmentRequest::new);
        this.environment = environment;
    }


    @Override
    protected void doExecute(
        Task task, NodeEnrollmentRequest request, ActionListener<NodeEnrollmentResponse> listener) {
        try {
            final String httpCa =
                Base64.getUrlEncoder().encodeToString(Files.readAllBytes(environment.configFile().resolve("httpCa.p12")));
            final String transportCa =
                Base64.getUrlEncoder().encodeToString(Files.readAllBytes(environment.configFile().resolve("transportCa.p12")));
            //TODO get cluster name and port from settings
            listener.onResponse(new NodeEnrollmentResponse(httpCa, transportCa, "test", 9300));
            Base64.getUrlEncoder().encodeToString(Files.readAllBytes(environment.configFile().resolve("httpCa.p12")));
        } catch (Exception e){
            throw new ElasticsearchSecurityException("zexceptionz");
        }
    }
}
