/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest.OpType;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.index.engine.VersionConflictEngineException;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.xpack.core.XPackField;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.ScrollHelper;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.core.security.authc.support.TokensInvalidationResult;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;


import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.elasticsearch.action.support.TransportActions.isShardNotAvailableException;
import static org.elasticsearch.search.SearchService.DEFAULT_KEEPALIVE_SETTING;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

/**
 * Service responsible for the creation, validation, and other management of {@link UserToken}
 * objects for authentication
 */
public final class TokenService {

    private static final String EXPIRED_TOKEN_WWW_AUTH_VALUE = "Bearer realm=\"" + XPackField.SECURITY +
        "\", error=\"invalid_token\", error_description=\"The access token expired\"";
    private static final String MALFORMED_TOKEN_WWW_AUTH_VALUE = "Bearer realm=\"" + XPackField.SECURITY +
        "\", error=\"invalid_token\", error_description=\"The access token is malformed\"";
    private static final String TYPE = "doc";

    public static final String THREAD_POOL_NAME = XPackField.SECURITY + "-token-key";
    public static final Setting<TimeValue> TOKEN_EXPIRATION = Setting.timeSetting("xpack.security.authc.token.timeout",
        TimeValue.timeValueMinutes(20L), TimeValue.timeValueSeconds(1L), Property.NodeScope);
    public static final Setting<TimeValue> DELETE_INTERVAL = Setting.timeSetting("xpack.security.authc.token.delete.interval",
        TimeValue.timeValueMinutes(30L), Property.NodeScope);
    public static final Setting<TimeValue> DELETE_TIMEOUT = Setting.timeSetting("xpack.security.authc.token.delete.timeout",
        TimeValue.MINUS_ONE, Property.NodeScope);

    private static final String TOKEN_DOC_TYPE = "token";
    private static final String TOKEN_DOC_ID_PREFIX = TOKEN_DOC_TYPE + "_";
    private static final int MAX_RETRY_ATTEMPTS = 5;
    private static final Logger logger = LogManager.getLogger(TokenService.class);

    private final Settings settings;
    private final Clock clock;
    private final TimeValue expirationDelay;
    private final TimeValue deleteInterval;
    private final Client client;
    private final SecurityIndexManager securityIndex;
    private final ExpiredTokenRemover expiredTokenRemover;
    private final boolean enabled;
    private volatile long lastExpirationRunMs;
    private final ClusterService clusterService;
    private static final Hasher HASHER = Hasher.SHA256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    /**
     * Creates a new token service
     *
     * @param settings the node settings
     * @param clock    the clock that will be used for comparing timestamps
     * @param client   the client to use when checking for revocations
     */
    public TokenService(Settings settings, Clock clock, Client client,
                        SecurityIndexManager securityIndex, ClusterService clusterService) {
        this.settings = settings;
        this.clock = clock.withZone(ZoneOffset.UTC);
        this.expirationDelay = TOKEN_EXPIRATION.get(settings);
        this.client = client;
        this.securityIndex = securityIndex;
        this.lastExpirationRunMs = client.threadPool().relativeTimeInMillis();
        this.deleteInterval = DELETE_INTERVAL.get(settings);
        this.enabled = isTokenServiceEnabled(settings);
        this.expiredTokenRemover = new ExpiredTokenRemover(settings, client);
        this.clusterService = clusterService;
    }

    public static Boolean isTokenServiceEnabled(Settings settings) {
        return XPackSettings.TOKEN_SERVICE_ENABLED_SETTING.get(settings);
    }

    /**
     * Create a token based on the provided authentication and metadata.
     * The created token will be stored in the security index.
     */
    public void createUserToken(Authentication authentication, Authentication originatingClientAuth,
                                ActionListener<Tuple<String, String>> listener, Map<String, Object> metadata,
                                boolean includeRefreshToken) throws IOException {
        ensureEnabled();
        if (authentication == null) {
            listener.onFailure(traceLog("create token", new IllegalArgumentException("authentication must be provided")));
        } else if (originatingClientAuth == null) {
            listener.onFailure(traceLog("create token",
                new IllegalArgumentException("originating client authentication must be provided")));
        } else {
            final Instant created = clock.instant();
            final Instant expiration = getExpirationTime(created);
            final Version version = clusterService.state().nodes().getMinNodeVersion();
            final Authentication matchingVersionAuth = version.equals(authentication.getVersion()) ? authentication :
                new Authentication(authentication.getUser(), authentication.getAuthenticatedBy(), authentication.getLookedUpBy(),
                    version);
            final UserToken userToken = new UserToken(version, matchingVersionAuth, expiration, metadata);
            final String refreshToken = includeRefreshToken ? UUIDs.randomBase64UUID() : null;

            try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                builder.startObject();
                builder.field("doc_type", TOKEN_DOC_TYPE);
                builder.field("creation_time", created.toEpochMilli());
                if (includeRefreshToken) {
                    builder.startObject("refresh_token")
                        .field("token", refreshToken)
                        .field("invalidated", false)
                        .field("refreshed", false)
                        .startObject("client")
                        .field("type", "unassociated_client")
                        .field("user", originatingClientAuth.getUser().principal())
                        .field("realm", originatingClientAuth.getAuthenticatedBy().getName())
                        .endObject()
                        .endObject();
                }
                builder.startObject("access_token")
                    .field("invalidated", false)
                    .field("user_token", userToken)
                    .field("realm", authentication.getAuthenticatedBy().getName())
                    .endObject();
                builder.endObject();
                final Tuple<String, String> tokenAndId = getAccessTokenAndId(userToken);
                IndexRequest request =
                    client.prepareIndex(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, tokenAndId.v2())
                        .setOpType(OpType.CREATE)
                        .setSource(builder)
                        .setRefreshPolicy(RefreshPolicy.WAIT_UNTIL)
                        .request();
                securityIndex.prepareIndexIfNeededThenExecute(ex -> listener.onFailure(traceLog("prepare security index", tokenAndId.v2(),
                    ex)),
                    () -> executeAsyncWithOrigin(client, SECURITY_ORIGIN, IndexAction.INSTANCE, request,
                        ActionListener.wrap(indexResponse -> listener.onResponse(new Tuple<>(tokenAndId.v1(), refreshToken)),
                            listener::onFailure))
                );
            }
        }
    }

    /**
     * Looks in the context to see if the request provided a header with a user token and if so the
     * token is validated, which includes authenticated decryption and verification that the token
     * has not been revoked or is expired.
     */
    void getAndValidateToken(ThreadContext ctx, ActionListener<UserToken> listener) {
        if (enabled) {
            final String token = getFromHeader(ctx);
            if (token == null) {
                listener.onResponse(null);
            } else {
                findTokenDocumentAsMap(token, ActionListener.wrap(documentMap -> {
                    if (documentMap != null) {
                        checkIfTokenIsValid(documentMap, listener);
                    } else {
                        listener.onResponse(null);
                    }
                }, listener::onFailure));
            }
        } else {
            listener.onResponse(null);
        }
    }

    /**
     * Reads the authentication and metadata from the given token.
     * This method does not validate whether the token is expired or not.
     */
    public void getAuthenticationAndMetaData(String token, ActionListener<Tuple<Authentication, Map<String, Object>>> listener) {
        findTokenDocumentAsMap(token, ActionListener.wrap(
            documentSource -> {
                if (documentSource == null) {
                    listener.onFailure(new ElasticsearchSecurityException("supplied token is not valid"));
                } else {
                    Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("find token document", token, ex));
                    Map<String, Object> accessTokenSource =
                        (Map<String, Object>) documentSource.get("access_token");
                    if (accessTokenSource == null) {
                        onFailure.accept(new IllegalStateException(
                            "token document is missing the access_token field"));
                    } else if (accessTokenSource.containsKey("user_token") == false) {
                        onFailure.accept(new IllegalStateException(
                            "token document is missing the user_token field"));
                    } else {
                        Map<String, Object> userTokenSource =
                            (Map<String, Object>) accessTokenSource.get("user_token");
                        final UserToken userToken = UserToken.fromSourceMap(userTokenSource);
                        listener.onResponse(new Tuple<>(userToken.getAuthentication(), userToken.getMetadata()));
                    }
                }
            },
            listener::onFailure
        ));
    }

    /*
     * Gets the corresponding Token Document source as a Map
     */
    void findTokenDocumentAsMap(String token, ActionListener<Map<String, Object>> listener) {
        if (securityIndex.isAvailable() == false) {
            logger.warn("failed to get token [{}] since index is not available", token);
            listener.onResponse(null);
        } else {
            securityIndex.checkIndexVersionThenExecute(
                ex -> listener.onFailure(traceLog("prepare security index", token, ex)), () -> {
                    final GetRequest getRequest = client.prepareGet(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE,
                        getDocIdFromToken(token)).request();
                    Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("find token document", token, ex));
                    executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, getRequest,
                        ActionListener.<GetResponse>wrap(response -> {
                            if (response.isExists()) {
                                listener.onResponse(response.getSource());
                            } else {
                                onFailure.accept(
                                    new IllegalStateException("token document is missing and must be present"));
                            }
                        }, e -> {
                            // if the index or the shard is not there / available we assume that
                            // the token is not valid
                            if (isShardNotAvailableException(e)) {
                                logger.warn("failed to get token [{}] since index is not available", token);
                                listener.onResponse(null);
                            } else {
                                logger.error(new ParameterizedMessage("failed to get token [{}]", token), e);
                                listener.onFailure(e);
                            }
                        }), client::get);
                });
        }
    }

    /**
     * This method performs the steps necessary to invalidate a token so that it may no longer be
     * used. The process of invalidation involves performing an update to
     * the token document and setting the <code>invalidated</code> field to <code>true</code>
     */
    public void invalidateAccessToken(String tokenString, ActionListener<TokensInvalidationResult> listener) {
        ensureEnabled();
        if (Strings.isNullOrEmpty(tokenString)) {
            logger.trace("No token-string provided");
            listener.onFailure(new IllegalArgumentException("token must be provided"));
        } else {
            maybeStartTokenRemover();
            findTokenDocumentAsMap(tokenString, ActionListener.wrap(documentSource -> {
                if (documentSource == null) {
                    listener.onFailure(new ElasticsearchSecurityException("supplied token is not valid"));
                } else {
                    Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("find token document", tokenString, ex));
                    Map<String, Object> accessTokenSource =
                        (Map<String, Object>) documentSource.get("access_token");
                    if (accessTokenSource == null) {
                        onFailure.accept(new IllegalStateException(
                            "token document is missing the access_token field"));
                    } else if (accessTokenSource.containsKey("user_token") == false) {
                        onFailure.accept(new IllegalStateException(
                            "token document is missing the user_token field"));
                    } else {
                        Map<String, Object> userTokenSource =
                            (Map<String, Object>) accessTokenSource.get("user_token");
                        final UserToken userToken = UserToken.fromSourceMap(userTokenSource);
                        final String docId = getAccessTokenAndId(userToken).v2();
                        indexInvalidation(Collections.singleton(docId), listener, new AtomicInteger(0), "access_token", null);
                    }
                }
            }, listener::onFailure));
        }
    }

    /**
     * This method performs the steps necessary to invalidate a token so that it may no longer be used.
     *
     * @see #invalidateAccessToken(String, ActionListener)
     */
    public void invalidateAccessToken(UserToken userToken, ActionListener<TokensInvalidationResult> listener) {
        ensureEnabled();
        if (userToken == null) {
            logger.trace("No access token provided");
            listener.onFailure(new IllegalArgumentException("token must be provided"));
        } else {
            maybeStartTokenRemover();
            final String docId = getAccessTokenAndId(userToken).v2();
            indexInvalidation(Collections.singleton(docId), listener, new AtomicInteger(0), "access_token", null);
        }
    }

    /**
     * This method performs the steps necessary to invalidate a refresh token so that it may no longer be used.
     *
     * @param refreshToken The string representation of the refresh token
     * @param listener     the listener to notify upon completion
     */
    public void invalidateRefreshToken(String refreshToken, ActionListener<TokensInvalidationResult> listener) {
        ensureEnabled();
        if (Strings.isNullOrEmpty(refreshToken)) {
            logger.trace("No refresh token provided");
            listener.onFailure(new IllegalArgumentException("refresh token must be provided"));
        } else {
            maybeStartTokenRemover();
            findTokenFromRefreshToken(refreshToken,
                ActionListener.wrap(tuple -> {
                    final String docId = tuple.v1().getHits().getAt(0).getId(); // token_andthehashhere
                    indexInvalidation(Collections.singletonList(docId), listener, tuple.v2(), "refresh_token", null);
                }, listener::onFailure), new AtomicInteger(0));
        }
    }

    /**
     * Invalidate all access tokens and all refresh tokens of a given {@code realmName} and/or of a given
     * {@code username} so that they may no longer be used
     *
     * @param realmName the realm of which the tokens should be invalidated
     * @param username  the username for which the tokens should be invalidated
     * @param listener  the listener to notify upon completion
     */
    public void invalidateActiveTokensForRealmAndUser(@Nullable String realmName, @Nullable String username,
                                                      ActionListener<TokensInvalidationResult> listener) {
        ensureEnabled();
        if (Strings.isNullOrEmpty(realmName) && Strings.isNullOrEmpty(username)) {
            logger.trace("No realm name or username provided");
            listener.onFailure(new IllegalArgumentException("realm name or username must be provided"));
        } else {
            if (Strings.isNullOrEmpty(realmName)) {
                findActiveTokensForUser(username, ActionListener.wrap(tokenTuples -> {
                    if (tokenTuples.isEmpty()) {
                        logger.warn("No tokens to invalidate for realm [{}] and username [{}]", realmName, username);
                        listener.onResponse(TokensInvalidationResult.emptyResult());
                    } else {
                        invalidateAllTokens(tokenTuples
                                .stream()
                                .map(t -> getAccessTokenAndId(t.v1()).v2())
                                .collect(Collectors.toList())
                            , listener);
                    }
                }, listener::onFailure));
            } else {
                Predicate filter = null;
                if (Strings.hasText(username)) {
                    filter = isOfUser(username);
                }
                findActiveTokensForRealm(realmName, ActionListener.wrap(tokenTuples -> {
                    if (tokenTuples.isEmpty()) {
                        logger.warn("No tokens to invalidate for realm [{}] and username [{}]", realmName, username);
                        listener.onResponse(TokensInvalidationResult.emptyResult());
                    } else {
                        invalidateAllTokens(tokenTuples
                                .stream()
                                .map(t -> getAccessTokenAndId(t.v1()).v2())
                                .collect(Collectors.toList())
                            , listener);
                    }
                }, listener::onFailure), filter);
            }
        }
    }

    /**
     * Invalidates a collection of access_token and refresh_token that were retrieved by
     * {@link TokenService#invalidateActiveTokensForRealmAndUser}
     *
     * @param tokenDocumentIds The document ids of the documents that contain the access tokens and the refresh tokens that should be
     *                         invalidated
     * @param listener          the listener to notify upon completion
     */
    private void invalidateAllTokens(Collection<String> tokenDocumentIds, ActionListener<TokensInvalidationResult> listener) {
        maybeStartTokenRemover();
        // Invalidate the refresh tokens first so that they cannot be used to get new
        // access tokens while we invalidate the access tokens we currently know about
        indexInvalidation(tokenDocumentIds, ActionListener.wrap(result ->
                indexInvalidation(tokenDocumentIds, listener, new AtomicInteger(result.getAttemptCount()),
                    "access_token", result),
            listener::onFailure), new AtomicInteger(0), "refresh_token", null);
    }

    /**
     * Performs the actual invalidation of a collection of tokens
     *
     * @param tokenDocumentIds   the Document Ids of the documents that contain the tokens that should be invalidated
     * @param listener       the listener to notify upon completion
     * @param attemptCount   the number of attempts to invalidate that have already been tried
     * @param srcPrefix      the prefix to use when constructing the doc to update, either refresh_token or access_token depending on
     *                       what type of tokens should be invalidated
     * @param previousResult if this not the initial attempt for invalidation, it contains the result of invalidating
     *                       tokens up to the point of the retry. This result is added to the result of the current attempt
     */
    private void indexInvalidation(Collection<String> tokenDocumentIds, ActionListener<TokensInvalidationResult> listener,
                                   AtomicInteger attemptCount, String srcPrefix, @Nullable TokensInvalidationResult previousResult) {
        if (tokenDocumentIds.isEmpty()) {
            logger.warn("No [{}] tokens provided for invalidation", srcPrefix);
            listener.onFailure(invalidGrantException("No tokens provided for invalidation"));
        } else if (attemptCount.get() > MAX_RETRY_ATTEMPTS) {
            logger.warn("Failed to invalidate [{}] tokens after [{}] attempts", tokenDocumentIds.size(),
                attemptCount.get());
            listener.onFailure(invalidGrantException("failed to invalidate tokens"));
        } else {
            BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
            for (String tokenDocumentId : tokenDocumentIds) {
                UpdateRequest request =
                    client.prepareUpdate(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, tokenDocumentId)
                    .setDoc(srcPrefix, Collections.singletonMap("invalidated", true))
                    .setFetchSource(srcPrefix, null)
                    .request();
                bulkRequestBuilder.add(request);
            }
            bulkRequestBuilder.setRefreshPolicy(RefreshPolicy.WAIT_UNTIL);
            securityIndex.prepareIndexIfNeededThenExecute(ex -> listener.onFailure(traceLog("prepare security index", ex)),
                () -> executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, bulkRequestBuilder.request(),
                    ActionListener.<BulkResponse>wrap(bulkResponse -> {
                        ArrayList<String> retryTokenDocIds = new ArrayList<>();
                        ArrayList<ElasticsearchException> failedRequestResponses = new ArrayList<>();
                        ArrayList<String> previouslyInvalidated = new ArrayList<>();
                        ArrayList<String> invalidated = new ArrayList<>();
                        if (null != previousResult) {
                            failedRequestResponses.addAll((previousResult.getErrors()));
                            previouslyInvalidated.addAll(previousResult.getPreviouslyInvalidatedTokens());
                            invalidated.addAll(previousResult.getInvalidatedTokens());
                        }
                        for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                            if (bulkItemResponse.isFailed()) {
                                Throwable cause = bulkItemResponse.getFailure().getCause();
                                final String failedTokenDocId = bulkItemResponse.getFailure().getId();
                                if (isShardNotAvailableException(cause)) {
                                    retryTokenDocIds.add(failedTokenDocId);
                                } else {
                                    traceLog("invalidate access token", failedTokenDocId, cause);
                                    failedRequestResponses.add(new ElasticsearchException("Error invalidating " + srcPrefix + ": ", cause));
                                }
                            } else {
                                UpdateResponse updateResponse = bulkItemResponse.getResponse();
                                if (updateResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                                    logger.debug("Invalidated [{}] for doc [{}]", srcPrefix, updateResponse.getGetResult().getId());
                                    invalidated.add(updateResponse.getGetResult().getId());
                                } else if (updateResponse.getResult() == DocWriteResponse.Result.NOOP) {
                                    previouslyInvalidated.add(updateResponse.getGetResult().getId());
                                }
                            }
                        }
                        if (retryTokenDocIds.isEmpty() == false) {
                            TokensInvalidationResult incompleteResult = new TokensInvalidationResult(invalidated, previouslyInvalidated,
                                failedRequestResponses, attemptCount.get());
                            attemptCount.incrementAndGet();
                            indexInvalidation(retryTokenDocIds, listener, attemptCount, srcPrefix, incompleteResult);
                        }
                        TokensInvalidationResult result = new TokensInvalidationResult(invalidated, previouslyInvalidated,
                            failedRequestResponses, attemptCount.get());
                        listener.onResponse(result);
                    }, e -> {
                        Throwable cause = ExceptionsHelper.unwrapCause(e);
                        traceLog("invalidate tokens", cause);
                        if (isShardNotAvailableException(cause)) {
                            attemptCount.incrementAndGet();
                            indexInvalidation(tokenDocumentIds, listener, attemptCount, srcPrefix, previousResult);
                        } else {
                            listener.onFailure(e);
                        }
                    }), client::bulk));
        }
    }

    /**
     * Uses the refresh token to refresh its associated token and returns the new token with an
     * updated expiration date to the listener
     */
    public void refreshToken(String refreshToken, ActionListener<Tuple<String, String>> listener) {
        ensureEnabled();
        findTokenFromRefreshToken(refreshToken,
            ActionListener.wrap(tuple -> {
                final Authentication userAuth = Authentication.readFromContext(client.threadPool().getThreadContext());
                final String tokenDocId = tuple.v1().getHits().getHits()[0].getId();
                innerRefresh(tokenDocId, userAuth, listener, tuple.v2());
            }, listener::onFailure),
            new AtomicInteger(0));
    }

    private void findTokenFromRefreshToken(String refreshToken, ActionListener<Tuple<SearchResponse, AtomicInteger>> listener,
                                           AtomicInteger attemptCount) {
        if (attemptCount.get() > MAX_RETRY_ATTEMPTS) {
            logger.warn("Failed to find token for refresh token [{}] after [{}] attempts", refreshToken, attemptCount.get());
            listener.onFailure(invalidGrantException("could not refresh the requested token"));
        } else {
            SearchRequest request = client.prepareSearch(SecurityIndexManager.SECURITY_INDEX_NAME)
                .setQuery(QueryBuilders.boolQuery()
                    .filter(QueryBuilders.termQuery("doc_type", TOKEN_DOC_TYPE))
                    .filter(QueryBuilders.termQuery("refresh_token.token", refreshToken)))
                .setVersion(true)
                .request();

            final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
            if (frozenSecurityIndex.indexExists() == false) {
                logger.warn("security index does not exist therefore refresh token [{}] cannot be validated", refreshToken);
                listener.onFailure(invalidGrantException("could not refresh the requested token"));
            } else if (frozenSecurityIndex.isAvailable() == false) {
                logger.debug("security index is not available to find token from refresh token, retrying");
                attemptCount.incrementAndGet();
                findTokenFromRefreshToken(refreshToken, listener, attemptCount);
            } else {
                Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("find by refresh token", refreshToken, ex));
                securityIndex.checkIndexVersionThenExecute(listener::onFailure, () ->
                    executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, request,
                        ActionListener.<SearchResponse>wrap(searchResponse -> {
                            if (searchResponse.isTimedOut()) {
                                attemptCount.incrementAndGet();
                                findTokenFromRefreshToken(refreshToken, listener, attemptCount);
                            } else if (searchResponse.getHits().getHits().length < 1) {
                                logger.info("could not find token document with refresh_token [{}]", refreshToken);
                                onFailure.accept(invalidGrantException("could not refresh the requested token"));
                            } else if (searchResponse.getHits().getHits().length > 1) {
                                onFailure.accept(new IllegalStateException("multiple tokens share the same refresh token"));
                            } else {
                                listener.onResponse(new Tuple<>(searchResponse, attemptCount));
                            }
                        }, e -> {
                            if (isShardNotAvailableException(e)) {
                                logger.debug("failed to search for token document, retrying", e);
                                attemptCount.incrementAndGet();
                                findTokenFromRefreshToken(refreshToken, listener, attemptCount);
                            } else {
                                onFailure.accept(e);
                            }
                        }),
                        client::search));
            }
        }
    }

    /**
     * Performs the actual refresh of the token with retries in case of certain exceptions that
     * may be recoverable. The refresh involves retrieval of the token document and then
     * updating the token document to indicate that the document has been refreshed.
     */
    private void innerRefresh(String tokenDocId, Authentication userAuth, ActionListener<Tuple<String, String>> listener,
                              AtomicInteger attemptCount) {
        if (attemptCount.getAndIncrement() > MAX_RETRY_ATTEMPTS) {
            logger.warn("Failed to refresh token for doc [{}] after [{}] attempts", tokenDocId, attemptCount.get());
            listener.onFailure(invalidGrantException("could not refresh the requested token"));
        } else {
            Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("refresh token", tokenDocId, ex));
            GetRequest getRequest = client.prepareGet(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, tokenDocId).request();
            executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, getRequest,
                ActionListener.<GetResponse>wrap(response -> {
                    if (response.isExists()) {
                        final Map<String, Object> source = response.getSource();
                        final Optional<ElasticsearchSecurityException> invalidSource = checkTokenDocForRefresh(source, userAuth);

                        if (invalidSource.isPresent()) {
                            onFailure.accept(invalidSource.get());
                        } else {
                            final Map<String, Object> userTokenSource = (Map<String, Object>)
                                ((Map<String, Object>) source.get("access_token")).get("user_token");
                            final String authString = (String) userTokenSource.get("authentication");
                            final Integer version = (Integer) userTokenSource.get("version");
                            final Map<String, Object> metadata = (Map<String, Object>) userTokenSource.get("metadata");

                            Version authVersion = Version.fromId(version);
                            try (StreamInput in = StreamInput.wrap(Base64.getDecoder().decode(authString))) {
                                in.setVersion(authVersion);
                                Authentication authentication = new Authentication(in);
                                UpdateRequest updateRequest =
                                    client.prepareUpdate(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, tokenDocId)
                                        .setVersion(response.getVersion())
                                        .setDoc("refresh_token", Collections.singletonMap("refreshed", true))
                                        .setRefreshPolicy(RefreshPolicy.WAIT_UNTIL)
                                        .request();
                                executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, updateRequest,
                                    ActionListener.<UpdateResponse>wrap(
                                        updateResponse -> createUserToken(authentication, userAuth, listener, metadata, true),
                                        e -> {
                                            Throwable cause = ExceptionsHelper.unwrapCause(e);
                                            if (cause instanceof VersionConflictEngineException ||
                                                isShardNotAvailableException(e)) {
                                                innerRefresh(tokenDocId, userAuth,
                                                    listener, attemptCount);
                                            } else {
                                                onFailure.accept(e);
                                            }
                                        }),
                                    client::update);
                            }
                        }
                    } else {
                        logger.info("could not find token document [{}] for refresh", tokenDocId);
                        onFailure.accept(invalidGrantException("could not refresh the requested token"));
                    }
                }, e -> {
                    if (isShardNotAvailableException(e)) {
                        innerRefresh(tokenDocId, userAuth, listener, attemptCount);
                    } else {
                        listener.onFailure(e);
                    }
                }), client::get);
        }
    }

    /**
     * Performs checks on the retrieved source and returns an {@link Optional} with the exception
     * if there is an issue
     */
    private Optional<ElasticsearchSecurityException> checkTokenDocForRefresh(Map<String, Object> source, Authentication userAuth) {
        final Map<String, Object> refreshTokenSrc = (Map<String, Object>) source.get("refresh_token");
        final Map<String, Object> accessTokenSrc = (Map<String, Object>) source.get("access_token");
        if (refreshTokenSrc == null || refreshTokenSrc.isEmpty()) {
            return Optional.of(invalidGrantException("token document is missing the refresh_token object"));
        } else if (accessTokenSrc == null || accessTokenSrc.isEmpty()) {
            return Optional.of(invalidGrantException("token document is missing the access_token object"));
        } else {
            final Boolean refreshed = (Boolean) refreshTokenSrc.get("refreshed");
            final Boolean invalidated = (Boolean) refreshTokenSrc.get("invalidated");
            final Long creationEpochMilli = (Long) source.get("creation_time");
            final Instant creationTime = creationEpochMilli == null ? null : Instant.ofEpochMilli(creationEpochMilli);
            final Map<String, Object> userTokenSrc = (Map<String, Object>) accessTokenSrc.get("user_token");
            if (refreshed == null) {
                return Optional.of(invalidGrantException("token document is missing refreshed value"));
            } else if (invalidated == null) {
                return Optional.of(invalidGrantException("token document is missing invalidated value"));
            } else if (creationEpochMilli == null) {
                return Optional.of(invalidGrantException("token document is missing creation time value"));
            } else if (refreshed) {
                return Optional.of(invalidGrantException("token has already been refreshed"));
            } else if (invalidated) {
                return Optional.of(invalidGrantException("token has been invalidated"));
            } else if (clock.instant().isAfter(creationTime.plus(24L, ChronoUnit.HOURS))) {
                return Optional.of(invalidGrantException("refresh token is expired"));
            } else if (userTokenSrc == null || userTokenSrc.isEmpty()) {
                return Optional.of(invalidGrantException("token document is missing the user token info"));
            } else if (userTokenSrc.get("authentication") == null) {
                return Optional.of(invalidGrantException("token is missing authentication info"));
            } else if (userTokenSrc.get("version") == null) {
                return Optional.of(invalidGrantException("token is missing version value"));
            } else if (userTokenSrc.get("metadata") == null) {
                return Optional.of(invalidGrantException("token is missing metadata"));
            } else {
                return checkClient(refreshTokenSrc, userAuth);
            }
        }
    }

    private Optional<ElasticsearchSecurityException> checkClient(Map<String, Object> refreshTokenSource, Authentication userAuth) {
        Map<String, Object> clientInfo = (Map<String, Object>) refreshTokenSource.get("client");
        if (clientInfo == null) {
            return Optional.of(invalidGrantException("token is missing client information"));
        } else if (userAuth.getUser().principal().equals(clientInfo.get("user")) == false) {
            return Optional.of(invalidGrantException("tokens must be refreshed by the creating client"));
        } else if (userAuth.getAuthenticatedBy().getName().equals(clientInfo.get("realm")) == false) {
            return Optional.of(invalidGrantException("tokens must be refreshed by the creating client"));
        } else {
            return Optional.empty();
        }
    }

    /**
     * Find stored refresh and access tokens that have not been invalidated or expired, and were issued against
     * the specified realm.
     *
     * @param realmName The name of the realm for which to get the tokens
     * @param listener  The listener to notify upon completion
     * @param filter    an optional Predicate to test the source of the found documents against
     */
    public void findActiveTokensForRealm(String realmName, ActionListener<Collection<Tuple<UserToken, String>>> listener,
                                         @Nullable Predicate<Map<String, Object>> filter) {
        ensureEnabled();
        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (Strings.isNullOrEmpty(realmName)) {
            listener.onFailure(new IllegalArgumentException("Realm name is required"));
        } else if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final Instant now = clock.instant();
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("doc_type", TOKEN_DOC_TYPE))
                .filter(QueryBuilders.termQuery("access_token.realm", realmName))
                .filter(QueryBuilders.boolQuery()
                    .should(QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("access_token.invalidated", false))
                        .must(QueryBuilders.rangeQuery("access_token.user_token.expiration_time").gte(now.toEpochMilli()))
                    )
                    .should(QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("refresh_token.invalidated", false))
                        .must(QueryBuilders.rangeQuery("creation_time").gte(now.toEpochMilli() - TimeValue.timeValueHours(24).millis()))
                    )
                );

            final SearchRequest request = client.prepareSearch(SecurityIndexManager.SECURITY_INDEX_NAME)
                .setScroll(DEFAULT_KEEPALIVE_SETTING.get(settings))
                .setQuery(boolQuery)
                .setVersion(false)
                .setSize(1000)
                .setFetchSource(true)
                .request();
            securityIndex.checkIndexVersionThenExecute(listener::onFailure,
                () -> ScrollHelper.fetchAllByEntity(client, request, listener, (SearchHit hit) -> filterAndParseHit(hit, filter)));
        }
    }

    /**
     * Find stored refresh and access tokens that have not been invalidated or expired, and were issued for
     * the specified user.
     *
     * @param username The user for which to get the tokens
     * @param listener The listener to notify upon completion
     */
    public void findActiveTokensForUser(String username, ActionListener<Collection<Tuple<UserToken, String>>> listener) {
        ensureEnabled();

        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (Strings.isNullOrEmpty(username)) {
            listener.onFailure(new IllegalArgumentException("username is required"));
        } else if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final Instant now = clock.instant();
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("doc_type", TOKEN_DOC_TYPE))
                .filter(QueryBuilders.boolQuery()
                    .should(QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("access_token.invalidated", false))
                        .must(QueryBuilders.rangeQuery("access_token.user_token.expiration_time").gte(now.toEpochMilli()))
                    )
                    .should(QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("refresh_token.invalidated", false))
                        .must(QueryBuilders.rangeQuery("creation_time").gte(now.toEpochMilli() - TimeValue.timeValueHours(24).millis()))
                    )
                );

            final SearchRequest request = client.prepareSearch(SecurityIndexManager.SECURITY_INDEX_NAME)
                .setScroll(DEFAULT_KEEPALIVE_SETTING.get(settings))
                .setQuery(boolQuery)
                .setVersion(false)
                .setSize(1000)
                .setFetchSource(true)
                .request();
            securityIndex.checkIndexVersionThenExecute(listener::onFailure,
                () -> ScrollHelper.fetchAllByEntity(client, request, listener,
                    (SearchHit hit) -> filterAndParseHit(hit, isOfUser(username))));
        }
    }

    private static Predicate<Map<String, Object>> isOfUser(String username) {
        return source -> {
            String auth = (String) source.get("authentication");
            Integer version = (Integer) source.get("version");
            Version authVersion = Version.fromId(version);
            try (StreamInput in = StreamInput.wrap(Base64.getDecoder().decode(auth))) {
                in.setVersion(authVersion);
                Authentication authentication = new Authentication(in);
                return authentication.getUser().principal().equals(username);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
    }


    private Tuple<UserToken, String> filterAndParseHit(SearchHit hit, @Nullable Predicate<Map<String, Object>> filter) {
        final Map<String, Object> source = hit.getSourceAsMap();
        if (source == null) {
            throw new IllegalStateException("token document did not have source but source should have been fetched");
        }
        try {
            return parseTokensFromDocument(source, filter);
        } catch (IOException e) {
            throw invalidGrantException("cannot read token from document");
        }
    }

    /**
     * Parses a token document into a Tuple of a {@link UserToken} and a String representing the corresponding refresh_token
     *
     * @param source The token document source as retrieved
     * @param filter an optional Predicate to test the source of the UserToken against
     * @return A {@link Tuple} of access-token and refresh-token-id or null if a Predicate is defined and the userToken source doesn't
     * satisfy it
     */
    private Tuple<UserToken, String> parseTokensFromDocument
    (Map<String, Object> source, @Nullable Predicate<Map<String, Object>> filter)
        throws IOException {

        final String refreshToken = (String) ((Map<String, Object>) source.get("refresh_token")).get("token");
        final Map<String, Object> userTokenSource = (Map<String, Object>)
            ((Map<String, Object>) source.get("access_token")).get("user_token");
        if (null != filter && filter.test(userTokenSource) == false) {
            return null;
        }
        final String id = (String) userTokenSource.get("id");
        final Integer version = (Integer) userTokenSource.get("version");
        final String authString = (String) userTokenSource.get("authentication");
        final Long expiration = (Long) userTokenSource.get("expiration_time");
        final Map<String, Object> metadata = (Map<String, Object>) userTokenSource.get("metadata");

        Version authVersion = Version.fromId(version);
        try (StreamInput in = StreamInput.wrap(Base64.getDecoder().decode(authString))) {
            in.setVersion(authVersion);
            Authentication authentication = new Authentication(in);
            return new Tuple<>(new UserToken(id, Version.fromId(version), authentication, Instant.ofEpochMilli(expiration), metadata),
                refreshToken);
        }
    }

    private static Tuple<String, String> getAccessTokenAndId(UserToken userToken) {
        return getAccessTokenAndId(userToken.getId());
    }

    private static Tuple<String, String> getAccessTokenAndId(String userTokenId) {
        final char[] hashedId = HASHER.hash(new SecureString(userTokenId));
        return new Tuple(new String(userTokenId), TOKEN_DOC_ID_PREFIX + new String(hashedId));
    }

    private static String getDocIdFromToken(String token) {
        return TOKEN_DOC_ID_PREFIX + new String(HASHER.hash(new SecureString(token.toCharArray())));
    }
    private static String getTokenIdFromDocumentId(String docId) {
        if (docId.startsWith(TOKEN_DOC_ID_PREFIX) == false) {
            throw new IllegalStateException("TokenDocument ID [" + docId + "] has unexpected value");
        } else {
            return docId.substring(TOKEN_DOC_ID_PREFIX.length());
        }
    }

    private static Tuple<String, String> hashRefreshToken(String tokenString) {
        final byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        final char[] saltChars = CharArrays.utf8BytesToChars(salt);
        final char[] a = new char[16 + tokenString.toCharArray().length];
        System.arraycopy(saltChars, 0, a, 0, saltChars.length);
        System.arraycopy(tokenString.toCharArray(), 0, a, saltChars.length, tokenString.toCharArray().length);
        final char[] hashedId = HASHER.hash(new SecureString(a));
        return new Tuple(new String(a), new String(hashedId));
    }

    private void ensureEnabled() {
        if (enabled == false) {
            throw new IllegalStateException("tokens are not enabled");
        }
    }

    /**
     * Checks if the access token has been explicitly invalidated
     */
    private void checkIfTokenIsValid(Map<String, Object> documentMap, ActionListener<UserToken> listener) {
        Consumer<Exception> onFailure = ex -> listener.onFailure(traceLog("check token state", ex));
        try {
            Map<String, Object> accessTokenSource = (Map<String, Object>) documentMap.get("access_token");
            if (accessTokenSource == null) {
                onFailure.accept(new IllegalStateException("token document is missing access_token field"));
            } else {
                Boolean invalidated = (Boolean) accessTokenSource.get("invalidated");
                if (invalidated == null) {
                    onFailure.accept(new IllegalStateException("token document is missing invalidated field"));
                } else if (invalidated) {
                    onFailure.accept(expiredTokenException());
                } else {
                    Map<String, Object> userTokenSource =
                        (Map<String, Object>) accessTokenSource.get("user_token");
                    final UserToken userToken = UserToken.fromSourceMap(userTokenSource);
                    Instant currentTime = clock.instant();
                    if (currentTime.isAfter(userToken.getExpirationTime())) {
                        listener.onFailure(traceLog("validate token", userToken.getId(), expiredTokenException()));
                    }
                    listener.onResponse(userToken);
                }
            }
        } catch (IOException e) {
            listener.onFailure(traceLog("validate token", e));
        }

    }

    public TimeValue getExpirationDelay() {
        return expirationDelay;
    }

    private Instant getExpirationTime(Instant now) {
        return now.plusSeconds(expirationDelay.getSeconds());
    }

    private void maybeStartTokenRemover() {
        if (securityIndex.isAvailable()) {
            if (client.threadPool().relativeTimeInMillis() - lastExpirationRunMs > deleteInterval.getMillis()) {
                expiredTokenRemover.submit(client.threadPool());
                lastExpirationRunMs = client.threadPool().relativeTimeInMillis();
            }
        }
    }

    /**
     * Gets the token from the <code>Authorization</code> header if the header begins with
     * <code>Bearer </code>
     */
    private String getFromHeader(ThreadContext threadContext) {
        String header = threadContext.getHeader("Authorization");
        if (Strings.hasText(header) && header.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())
            && header.length() > "Bearer ".length()) {
            return header.substring("Bearer ".length());
        }
        return null;
    }

    /**
     * Creates an {@link ElasticsearchSecurityException} that indicates the token was expired. It
     * is up to the client to re-authenticate and obtain a new token. The format for this response
     * is defined in <a href="https://tools.ietf.org/html/rfc6750#section-3.1"></a>
     */
    private static ElasticsearchSecurityException expiredTokenException() {
        ElasticsearchSecurityException e =
            new ElasticsearchSecurityException("token expired", RestStatus.UNAUTHORIZED);
        e.addHeader("WWW-Authenticate", EXPIRED_TOKEN_WWW_AUTH_VALUE);
        return e;
    }

    /**
     * Creates an {@link ElasticsearchSecurityException} that indicates the token was malformed. It
     * is up to the client to re-authenticate and obtain a new token. The format for this response
     * is defined in <a href="https://tools.ietf.org/html/rfc6750#section-3.1"></a>
     */
    private static ElasticsearchSecurityException malformedTokenException() {
        ElasticsearchSecurityException e =
            new ElasticsearchSecurityException("token malformed", RestStatus.UNAUTHORIZED);
        e.addHeader("WWW-Authenticate", MALFORMED_TOKEN_WWW_AUTH_VALUE);
        return e;
    }

    /**
     * Creates an {@link ElasticsearchSecurityException} that indicates the request contained an invalid grant
     */
    private static ElasticsearchSecurityException invalidGrantException(String detail) {
        ElasticsearchSecurityException e =
            new ElasticsearchSecurityException("invalid_grant", RestStatus.BAD_REQUEST);
        e.addHeader("error_description", detail);
        return e;
    }

    /**
     * Logs an exception concerning a specific Token at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, String identifier, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}] - [{}]", action, identifier, detail),
                        esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier),
                        esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier), exception);
            }
        }
        return exception;
    }

    /**
     * Logs an exception at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] - [{}]", action, detail), esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), exception);
            }
        }
        return exception;
    }

    boolean isExpiredTokenException(ElasticsearchSecurityException e) {
        final List<String> headers = e.getHeader("WWW-Authenticate");
        return headers != null && headers.stream().anyMatch(EXPIRED_TOKEN_WWW_AUTH_VALUE::equals);
    }

    boolean isExpirationInProgress() {
        return expiredTokenRemover.isExpirationInProgress();
    }

}
