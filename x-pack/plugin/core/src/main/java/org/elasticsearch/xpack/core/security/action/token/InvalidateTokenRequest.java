/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.token;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

import static org.elasticsearch.action.ValidateActions.addValidationError;

/**
 * Request for invalidating a token so that it can no longer be used
 */
public final class InvalidateTokenRequest extends ActionRequest {

    public enum Type {
        ACCESS_TOKEN("token"),
        REFRESH_TOKEN("refresh_token");

        private final String value;

        Type(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static Type fromString(String tokenType) {
            if (tokenType != null) {
                for (Type type : values()) {
                    if (type.getValue().equals(tokenType)) {
                        return type;
                    }
                }
            }
            return null;
        }
    }

    private String tokenString;
    private Type tokenType;
    private String realmName;
    private String userName;

    public InvalidateTokenRequest() {}

    /**
     * @param tokenString the string representation of the token to be invalidated
     * @param tokenType the type of the token to be invalidated
     * @param realmName the name of the realm for which all tokens will be invalidated
     * @param userName the principal of the user for which all tokens will be invalidated
     */
    public InvalidateTokenRequest(@Nullable String tokenString, @Nullable String tokenType, @Nullable String realmName, @Nullable String userName) {
        this.tokenString = tokenString;
        this.tokenType = Type.fromString(tokenType);
        this.realmName = realmName;
        this.userName = userName;
    }

    /**
     * @param tokenString the string representation of the token to be invalidated
     * @param tokenType   the type of the token to be invalidated
     */
    public InvalidateTokenRequest(String tokenString, String tokenType) {
        this.tokenString = tokenString;
        this.tokenType = Type.fromString(tokenType);
        this.realmName = null;
        this.userName = null;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.hasText(realmName)) {
            if (Strings.hasText(tokenString)) {
                validationException = addValidationError("token string must not be provided when realm name is specified", null);
            }
            if (tokenType != null) {
                validationException = addValidationError("token type must not be provided when realm name is specified", null);
            }
        } else if (Strings.hasText(userName)) {
            if (Strings.hasText(tokenString)) {
                validationException = addValidationError("token string must not be provided when username is specified", null);
            }
            if (tokenType != null) {
                validationException = addValidationError("token type must not be provided when username is specified", null);
            }
        } else {
            if (Strings.isNullOrEmpty(tokenString)) {
                validationException =
                    addValidationError("token string must be provided when not specifying a realm name or a username", null);
            }
            if (tokenType == null) {
                validationException =
                    addValidationError("token type must be provided when a token string is specified", null);
            }
        }
        return validationException;
    }

    public String getTokenString() {
        return tokenString;
    }

    void setTokenString(String token) {
        this.tokenString = token;
    }

    public Type getTokenType() {
        return tokenType;
    }

    void setTokenType(Type tokenType) {
        this.tokenType = tokenType;
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(tokenString);
        if (out.getVersion().onOrAfter(Version.V_6_2_0)) {
            out.writeOptionalVInt(tokenType == null ? null : tokenType.ordinal());
        } else if (tokenType == Type.REFRESH_TOKEN) {
            throw new IllegalArgumentException("refresh token invalidation cannot be serialized with version [" + out.getVersion() + "]");
        }
        if (out.getVersion().onOrAfter(Version.V_6_6_0)) {
            out.writeOptionalString(realmName);
            out.writeOptionalString(userName);
        } else {
            throw new IllegalArgumentException("realm token invalidation cannot be serialized with version [" + out.getVersion() + "]");
        }
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        tokenString = in.readOptionalString();
        if (in.getVersion().onOrAfter(Version.V_6_2_0)) {
            Integer type = in.readOptionalVInt();
            tokenType = type == null ? null : Type.values()[type];
        } else {
            tokenType = Type.ACCESS_TOKEN;
        }
        if (in.getVersion().onOrAfter(Version.V_6_6_0)) {
            realmName = in.readOptionalString();
            userName = in.readOptionalString();
        }
    }
}
