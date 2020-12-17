/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;

public class RestNodeEnrollmentAction extends SecurityBaseRestHandler {

    public RestNodeEnrollmentAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override protected RestChannelConsumer innerPrepareRequest(
        RestRequest request, NodeClient client) throws IOException {
        return null;
    }

    @Override public String getName() {
        return "security_enroll_action";
    }

    @Override public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, "_security/enroll"));
    }
}
