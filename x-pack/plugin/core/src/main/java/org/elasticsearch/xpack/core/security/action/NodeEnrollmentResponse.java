/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

public class NodeEnrollmentResponse extends ActionResponse implements ToXContentObject {

    private static final ParseField HTTP_CA = new ParseField("http_ca");
    private static final ParseField TRANSPORT_CA = new ParseField("transport_ca");
    private static final ParseField CLUSTER_NAME = new ParseField("cluster_name");
    private static final ParseField TRANSPORT_PORT = new ParseField("transport_port");

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

    public NodeEnrollmentResponse(String httpKeystore, String transportKeystore, String clusterName, int transportPort){
        this.httpKeystore = httpKeystore;
        this.transportKeystore = transportKeystore;
        this.clusterName = clusterName;
        this.transportPort = transportPort;
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

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(httpKeystore);
        out.writeString(transportKeystore);
        out.writeString(clusterName);
        out.writeInt(transportPort);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        builder.field(HTTP_CA.getPreferredName(), httpKeystore);
        builder.field(TRANSPORT_CA.getPreferredName(), transportKeystore);
        builder.field(CLUSTER_NAME.getPreferredName(), clusterName);
        builder.field(TRANSPORT_PORT.getPreferredName(), transportPort);
        return builder.endObject();
    }
}
