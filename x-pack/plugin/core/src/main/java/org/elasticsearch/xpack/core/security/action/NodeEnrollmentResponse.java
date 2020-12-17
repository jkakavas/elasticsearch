/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class NodeEnrollmentResponse extends ActionResponse {

    private String httpKeystore;
    private String transportKeystore;
    private String clusterName;
    private int transportPort;

    public NodeEnrollmentResponse(StreamInput in) throws IOException{
        super(in);
        httpKeystore = in.readString();
        transportKeystore = in.readString();
        clusterName = in.readString();
        transportPort = in.readInt();
    }

    public String getHttpKeystore() {
        return httpKeystore;
    }

    public String getTransportKeystore() {
        return transportKeystore;
    }

    public String getClusterName() {
        return clusterName;
    }

    public int getTransportPort() {
        return transportPort;
    }

    @Override public void writeTo(StreamOutput out) throws IOException {
        out.writeString(httpKeystore);
        out.writeString(transportKeystore);
        out.writeString(clusterName);
        out.writeInt(transportPort);
    }
}
