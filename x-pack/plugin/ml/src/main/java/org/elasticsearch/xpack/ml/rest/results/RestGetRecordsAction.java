/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.ml.rest.results;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.core.RestApiVersion;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.core.action.util.PageParams;
import org.elasticsearch.xpack.core.ml.action.GetRecordsAction;
import org.elasticsearch.xpack.core.ml.job.config.Job;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.xpack.ml.MachineLearning.BASE_PATH;
import static org.elasticsearch.xpack.ml.MachineLearning.PRE_V7_BASE_PATH;

public class RestGetRecordsAction extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return org.elasticsearch.core.List.of(
            Route.builder(GET, BASE_PATH + "anomaly_detectors/{" + Job.ID + "}/results/records")
                .replaces(GET, PRE_V7_BASE_PATH + "anomaly_detectors/{" + Job.ID + "}/results/records", RestApiVersion.V_7).build(),
            Route.builder(POST, BASE_PATH + "anomaly_detectors/{" + Job.ID + "}/results/records")
                .replaces(POST, PRE_V7_BASE_PATH + "anomaly_detectors/{" + Job.ID + "}/results/records", RestApiVersion.V_7).build()
        );
    }

    @Override
    public String getName() {
        return "ml_get_records_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient client) throws IOException {
        String jobId = restRequest.param(Job.ID.getPreferredName());
        final GetRecordsAction.Request request;
        if (restRequest.hasContentOrSourceParam()) {
            XContentParser parser = restRequest.contentOrSourceParamParser();
            request = GetRecordsAction.Request.parseRequest(jobId, parser);
        }
        else {
            request = new GetRecordsAction.Request(jobId);
            request.setStart(restRequest.param(GetRecordsAction.Request.START.getPreferredName()));
            request.setEnd(restRequest.param(GetRecordsAction.Request.END.getPreferredName()));
            request.setExcludeInterim(restRequest.paramAsBoolean(GetRecordsAction.Request.EXCLUDE_INTERIM.getPreferredName(),
                    request.isExcludeInterim()));
            request.setPageParams(new PageParams(restRequest.paramAsInt(PageParams.FROM.getPreferredName(), PageParams.DEFAULT_FROM),
                    restRequest.paramAsInt(PageParams.SIZE.getPreferredName(), PageParams.DEFAULT_SIZE)));
            request.setRecordScore(
                    Double.parseDouble(restRequest.param(GetRecordsAction.Request.RECORD_SCORE_FILTER.getPreferredName(),
                            String.valueOf(request.getRecordScoreFilter()))));
            request.setSort(restRequest.param(GetRecordsAction.Request.SORT.getPreferredName(), request.getSort()));
            request.setDescending(restRequest.paramAsBoolean(GetRecordsAction.Request.DESCENDING.getPreferredName(),
                    request.isDescending()));
        }

        return channel -> client.execute(GetRecordsAction.INSTANCE, request, new RestToXContentListener<>(channel));
    }
}
