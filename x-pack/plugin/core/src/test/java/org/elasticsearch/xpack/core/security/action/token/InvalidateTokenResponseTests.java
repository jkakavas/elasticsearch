/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.token;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.VersionUtils;
import org.elasticsearch.xpack.core.security.authc.support.TokensInvalidationResult;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.Matchers.equalTo;

public class InvalidateTokenResponseTests extends ESTestCase {

    public void testSerialization() throws IOException {
        TokensInvalidationResult result = new TokensInvalidationResult(Arrays.asList(generateRandomStringArray(20, 15, false)),
            Arrays.asList(generateRandomStringArray(20, 15, false)),
            Arrays.asList(new ElasticsearchException("foo", new IllegalArgumentException("this is an error message")),
                new ElasticsearchException("bar", new IllegalArgumentException("this is an error message2"))),
            randomIntBetween(0, 5));
        InvalidateTokenResponse response = new InvalidateTokenResponse(result);
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            response.writeTo(output);
            try (StreamInput input = output.bytes().streamInput()) {
                InvalidateTokenResponse serialized = new InvalidateTokenResponse();
                serialized.readFrom(input);
                assertEquals(response, serialized);
            }
        }

        result = new TokensInvalidationResult(Arrays.asList(generateRandomStringArray(20, 15, false)),
            Arrays.asList(generateRandomStringArray(20, 15, false)),
            Collections.emptyList(), randomIntBetween(0, 5));
        response = new InvalidateTokenResponse(result);
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            response.writeTo(output);
            try (StreamInput input = output.bytes().streamInput()) {
                InvalidateTokenResponse serialized = new InvalidateTokenResponse();
                serialized.readFrom(input);
                assertEquals(response, serialized);
            }
        }
    }

    public void testSerializationToPre66Version() throws IOException{
        final Version version = VersionUtils.randomVersionBetween(random(), Version.V_6_2_0, Version.V_6_5_1);
        TokensInvalidationResult result = new TokensInvalidationResult(Arrays.asList(generateRandomStringArray(20, 15, false, false)),
            Arrays.asList(generateRandomStringArray(20, 15, false, false)),
            Arrays.asList(new ElasticsearchException("foo", new IllegalArgumentException("this is an error message")),
                new ElasticsearchException("bar", new IllegalArgumentException("this is an error message2"))),
            randomIntBetween(0, 5));
        InvalidateTokenResponse response = new InvalidateTokenResponse(result);
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            output.setVersion(version);
            response.writeTo(output);
            try (StreamInput input = output.bytes().streamInput()) {
                // False as we have errors and previously invalidated tokens
                assertThat(input.readBoolean(), equalTo(false));
            }
        }

        result = new TokensInvalidationResult(Arrays.asList(generateRandomStringArray(20, 15, false, false)),
            Arrays.asList(generateRandomStringArray(20, 15, false, false)),
            Collections.emptyList(), randomIntBetween(0, 5));
        response = new InvalidateTokenResponse(result);
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            output.setVersion(version);
            response.writeTo(output);
            try (StreamInput input = output.bytes().streamInput()) {
                // False as we have previously invalidated tokens
                assertThat(input.readBoolean(), equalTo(false));
            }
        }

        result = new TokensInvalidationResult(Arrays.asList(generateRandomStringArray(20, 15, false, false)),
            Collections.emptyList(), Collections.emptyList(), randomIntBetween(0, 5));
        response = new InvalidateTokenResponse(result);
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            output.setVersion(version);
            response.writeTo(output);
            try (StreamInput input = output.bytes().streamInput()) {
                assertThat(input.readBoolean(), equalTo(true));
            }
        }
    }
}
