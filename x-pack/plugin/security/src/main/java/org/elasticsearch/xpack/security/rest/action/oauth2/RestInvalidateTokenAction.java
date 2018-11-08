/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.rest.action.oauth2;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xpack.core.security.action.token.InvalidateTokenAction;
import org.elasticsearch.xpack.core.security.action.token.InvalidateTokenRequest;
import org.elasticsearch.xpack.core.security.action.token.InvalidateTokenResponse;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.io.IOException;

import static org.elasticsearch.rest.RestRequest.Method.DELETE;

/**
 * Rest handler for handling access token invalidation requests
 */
public final class RestInvalidateTokenAction extends SecurityBaseRestHandler {

    static final ConstructingObjectParser<InvalidateTokenRequest, Void> PARSER =
        new ConstructingObjectParser<>("invalidate_token", a ->
            new InvalidateTokenRequest((String) a[0], (String) a[1], (String) a[2], (String) a[3]));

    static {
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("token"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("refresh_token"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("realm_name"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("username"));
    }

    public RestInvalidateTokenAction(Settings settings, RestController controller, XPackLicenseState xPackLicenseState) {
        super(settings, xPackLicenseState);
        controller.registerHandler(DELETE, "/_xpack/security/oauth2/token", this);
    }

    @Override
    public String getName() {
        return "xpack_security_invalidate_token_action";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            final InvalidateTokenRequest tokenRequest = PARSER.parse(parser, null);
            return channel -> client.execute(InvalidateTokenAction.INSTANCE, tokenRequest,
                new RestBuilderListener<InvalidateTokenResponse>(channel) {
                    @Override
                    public RestResponse buildResponse(InvalidateTokenResponse invalidateResp,
                                                      XContentBuilder builder) throws Exception {
                        invalidateResp.toXContent(builder, channel.request());
                        return new BytesRestResponse(RestStatus.OK, builder);
                    }
                });
        }
    }
}
