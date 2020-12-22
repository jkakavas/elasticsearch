/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentAction;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentRequest;
import org.elasticsearch.xpack.core.security.action.NodeEnrollmentResponse;

import java.io.IOException;
import java.util.List;

public class RestNodeEnrollmentAction extends SecurityBaseRestHandler {

    public RestNodeEnrollmentAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override protected RestChannelConsumer innerPrepareRequest(
        RestRequest request, NodeClient client) throws IOException {
        return restChannel -> client.execute(NodeEnrollmentAction.INSTANCE, new NodeEnrollmentRequest(),
            new RestBuilderListener<NodeEnrollmentResponse>(restChannel) {
                @Override
                public RestResponse buildResponse(
                    NodeEnrollmentResponse nodeEnrollmentResponse, XContentBuilder builder) throws Exception {
                    nodeEnrollmentResponse.toXContent(builder, channel.request());
                    return new BytesRestResponse(RestStatus.OK, builder);
                }
            });
    }

    @Override public String getName() {
        return "security_enroll_action";
    }

    @Override public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, "_security/enroll"));
    }
}
