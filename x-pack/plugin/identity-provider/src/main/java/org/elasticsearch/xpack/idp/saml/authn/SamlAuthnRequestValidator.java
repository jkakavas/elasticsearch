/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.idp.saml.authn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.core.internal.io.Streams;
import org.elasticsearch.rest.RestUtils;
import org.elasticsearch.xpack.idp.action.SamlValidateAuthnRequestResponse;
import org.elasticsearch.xpack.idp.saml.idp.SamlIdentityProvider;
import org.elasticsearch.xpack.idp.saml.sp.SamlServiceProvider;
import org.elasticsearch.xpack.idp.saml.support.SamlUtils;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.security.x509.X509Credential;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static org.opensaml.saml.saml2.core.NameIDType.UNSPECIFIED;


/*
 * Processes a SAML AuthnRequest, validates it and extracts necessary information
 */
public class SamlAuthnRequestValidator {

    private final SamlIdentityProvider idp;
    private final Logger logger = LogManager.getLogger(SamlAuthnRequestValidator.class);
    private static final String[] XSD_FILES = new String[]{"/org/elasticsearch/xpack/idp/saml/support/saml-schema-protocol-2.0.xsd",
        "/org/elasticsearch/xpack/idp/saml/support/saml-schema-assertion-2.0.xsd",
        "/org/elasticsearch/xpack/idp/saml/support/xenc-schema.xsd",
        "/org/elasticsearch/xpack/idp/saml/support/xmldsig-core-schema.xsd"};

    private static final ThreadLocal<DocumentBuilder> THREAD_LOCAL_DOCUMENT_BUILDER = ThreadLocal.withInitial(() -> {
        try {
            return SamlUtils.getHardenedBuilder(XSD_FILES);
        } catch (Exception e) {
            throw new ElasticsearchSecurityException("Could not load XSD schema file", e);
        }
    });

    public SamlAuthnRequestValidator(SamlIdentityProvider idp) {
        SamlUtils.initialize();
        this.idp = idp;
    }

    public void processQueryString(String queryString, ActionListener<SamlValidateAuthnRequestResponse> listener) {
        try {
            final Map<String, String> parameters = new HashMap<>();
            RestUtils.decodeQueryString(queryString, 0, parameters);
            if (parameters.isEmpty()) {
                logAndRespond("Invalid Authentication Request query string", listener);
            }
            logger.trace(new ParameterizedMessage("Parsed the following parameters from the query string: {}", parameters));
            final String samlRequest = parameters.get("SAMLRequest");
            final String relayState = parameters.get("RelayState");
            final String sigAlg = parameters.get("SigAlg");
            final String signature = parameters.get("Signature");
            if (null == samlRequest) {
                logAndRespond(new ParameterizedMessage("Query string [{}] does not contain a SAMLRequest parameter", queryString),
                    listener);
                return;
            }
            // We consciously parse the AuthnRequest before we validate its signature as we need to get the Issuer, in order to
            // verify if we know of this SP and get its credentials for signature verification
            final Element root = parseSamlMessage(inflate(decodeBase64(samlRequest)));
            if (SamlUtils.elementNameMatches(root, "urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest") == false) {
                logAndRespond(new ParameterizedMessage("SAML message [{}] is not an AuthnRequest", SamlUtils.text(root, 128)), listener);
                return;
            }
            final AuthnRequest authnRequest = SamlUtils.buildXmlObject(root, AuthnRequest.class);
            final SamlServiceProvider sp = getSpFromIssuer(authnRequest.getIssuer());
            // If the Service Provider should not sign requests, do not try to handle signatures even if they are added to the request
            if (sp.shouldSignAuthnRequests()) {
                if (Strings.hasText(signature)) {
                    if (Strings.hasText(sigAlg) == false) {
                        logAndRespond(new ParameterizedMessage("Query string [{}] contains a Signature but SigAlg parameter is missing",
                            queryString), listener);
                        return;
                    }
                    final X509Credential spSigningCredential = sp.getSigningCredential();
                    if (spSigningCredential == null) {
                        logAndRespond(
                            "Unable to validate signature of authentication request, " +
                                "Service Provider hasn't registered signing credentials",
                            listener);
                        return;
                    }
                    if (validateSignature(samlRequest, sigAlg, signature, sp.getSigningCredential(), relayState) == false) {
                        logAndRespond(
                            new ParameterizedMessage("Unable to validate signature of authentication request [{}] using credentials [{}]",
                            queryString, SamlUtils.describeCredentials(Collections.singletonList(sp.getSigningCredential()))), listener);
                        return;
                    }
                } else if (Strings.hasText(sigAlg)) {
                    logAndRespond(new ParameterizedMessage("Query string [{}] contains a SigAlg parameter but Signature is missing",
                        queryString), listener);
                    return;
                } else {
                    logAndRespond("The Service Provider must sign authentication requests but no signature was found", listener);
                    return;
                }
            }
            validateAuthnRequest(authnRequest, sp);
            Map<String, Object> authnState = buildAuthnState(authnRequest, sp);
            final SamlValidateAuthnRequestResponse response = new SamlValidateAuthnRequestResponse(sp.getEntityId(),
                authnRequest.isForceAuthn(), authnState);
            logger.trace(new ParameterizedMessage("Validated AuthnResponse from queryString [{}] and extracted [{}]",
                queryString, response));
            listener.onResponse(response);
        } catch (ElasticsearchSecurityException e) {
            listener.onFailure(e);
        } catch (Exception e) {
            logAndRespond("Could not process and validate AuthnRequest", e, listener);
        }
    }

    private Map<String, Object> buildAuthnState(AuthnRequest request, SamlServiceProvider sp) {
        Map<String, Object> authnState = new HashMap<>();
        final NameIDPolicy nameIDPolicy = request.getNameIDPolicy();
        if (null != nameIDPolicy) {
            final String requestedFormat = request.getNameIDPolicy().getFormat();
            if (Strings.hasText(requestedFormat)) {
                authnState.put("nameid_format", requestedFormat);
                // we should not throw an error. Pass this as additional data so that the /saml/init API can
                // return a SAML response with the appropriate status (3.4.1.1 in the core spec)
                if (requestedFormat.equals(UNSPECIFIED) == false &&
                    requestedFormat.equals(sp.getNameIDPolicyFormat()) == false) {
                    logger.warn(() ->
                        new ParameterizedMessage("The requested NameID format [{}] doesn't match the allowed NameID format" +
                            "for this Service Provider is [{}]", requestedFormat, sp.getNameIDPolicyFormat()));
                    authnState.put("error", "invalid_nameid_policy");
                }
            }
        }
        return authnState;
    }

    private void validateAuthnRequest(AuthnRequest authnRequest, SamlServiceProvider sp) {
        checkDestination(authnRequest);
        checkAcs(authnRequest, sp);
    }

    private boolean validateSignature(String samlRequest, String sigAlg, String signature, X509Credential credential,
                                      @Nullable String relayState) {
        try {
            final String queryParam = relayState == null ?
                "SAMLRequest=" + urlEncode(samlRequest) + "&SigAlg=" + urlEncode(sigAlg) :
                "SAMLRequest=" + urlEncode(samlRequest) + "&RelayState=" + urlEncode(relayState) + "&SigAlg=" + urlEncode(sigAlg);
            Signature sig = Signature.getInstance(getJavaAlorithmNameFromUri(sigAlg));
            sig.initVerify(credential.getEntityCertificate().getPublicKey());
            sig.update(queryParam.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            throw new ElasticsearchSecurityException("Unable to validate signature of authentication request using credentials [{}]",
                SamlUtils.describeCredentials(Collections.singletonList(credential)), e);
        }
    }

    private SamlServiceProvider getSpFromIssuer(Issuer issuer) {
        if (issuer == null || issuer.getValue() == null) {
            throw new ElasticsearchSecurityException("SAML authentication request has no issuer");
        }
        final String issuerString = issuer.getValue();
        final SamlServiceProvider serviceProvider = idp.getRegisteredServiceProvider(issuerString);
        if (null == serviceProvider) {
            throw new ElasticsearchSecurityException("Service Provider with Entity ID [{}] is not registered with this Identity Provider",
                issuerString);
        }
        return serviceProvider;
    }

    private void checkDestination(AuthnRequest request) {
        final String url = idp.getSingleSignOnEndpoint("redirect");
        if (url.equals(request.getDestination()) == false) {
            throw new ElasticsearchSecurityException(
                "SAML authentication request [{}] is for destination [{}] but the SSO endpoint of this Identity Provider is [{}]",
                request.getID(), request.getDestination(), url);
        }
    }

    private void checkAcs(AuthnRequest request, SamlServiceProvider sp) {
        final String acs = request.getAssertionConsumerServiceURL();
        if (Strings.hasText(acs) == false) {
            final String message = request.getAssertionConsumerServiceIndex() == null ?
                "SAML authentication does not contain an AssertionConsumerService URL" :
                "SAML authentication does not contain an AssertionConsumerService URL. It contains an Assertion Consumer Service Index " +
                    "but this IDP doesn't support multiple AssertionConsumerService URLs.";
            throw new ElasticsearchSecurityException(message);
        }
        if (acs.equals(sp.getAssertionConsumerService()) == false) {
            throw new ElasticsearchSecurityException("The registered ACS URL for this Service Provider is [{}] but the authentication " +
                "request contained [{}]", sp.getAssertionConsumerService(), acs);
        }
    }

    protected Element parseSamlMessage(byte[] content) {
        final Element root;
        try (ByteArrayInputStream input = new ByteArrayInputStream(content)) {
            // This will parse and validate the input against the schemas
            final Document doc = THREAD_LOCAL_DOCUMENT_BUILDER.get().parse(input);
            root = doc.getDocumentElement();
            if (logger.isTraceEnabled()) {
                logger.trace("Received SAML Message: {} \n", SamlUtils.toString(root, true));
            }
        } catch (SAXException | IOException e) {
            throw new ElasticsearchSecurityException("Failed to parse SAML message", e);
        }
        return root;
    }

    private byte[] decodeBase64(String content) {
        try {
            return Base64.getDecoder().decode(content.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            logger.info("Failed to decode base64 string [{}] - {}", content, e);
            throw new ElasticsearchSecurityException("SAML message cannot be Base64 decoded", e);
        }
    }

    private byte[] inflate(byte[] bytes) {
        Inflater inflater = new Inflater(true);
        try (ByteArrayInputStream in = new ByteArrayInputStream(bytes);
             InflaterInputStream inflate = new InflaterInputStream(in, inflater);
             ByteArrayOutputStream out = new ByteArrayOutputStream(bytes.length * 3 / 2)) {
            Streams.copy(inflate, out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new ElasticsearchSecurityException("SAML message cannot be inflated", e);
        }
    }

    private String getJavaAlorithmNameFromUri(String sigAlg) {
        switch (sigAlg) {
            case "http://www.w3.org/2000/09/xmldsig#dsa-sha1":
                return "SHA1withDSA";
            case "http://www.w3.org/2000/09/xmldsig#dsa-sha256":
                return "SHA256withDSA";
            case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                return "SHA1withRSA";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                return "SHA256withRSA";
            case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
                return "SHA256withECDSA";
            default:
                throw new IllegalArgumentException("Unsupported signing algorithm identifier: " + sigAlg);
        }
    }

    private String urlEncode(String param) throws UnsupportedEncodingException {
        return URLEncoder.encode(param, StandardCharsets.UTF_8.name());
    }

    private void logAndRespond(String message, ActionListener listener) {
        logger.debug(message);
        listener.onFailure(new ElasticsearchSecurityException(message));
    }

    private void logAndRespond(String message, Throwable e, ActionListener listener) {
        logger.debug(message);
        listener.onFailure(new ElasticsearchSecurityException(message, e));
    }

    private void logAndRespond(ParameterizedMessage message, ActionListener listener) {
        logger.debug(message.getFormattedMessage());
        listener.onFailure(new ElasticsearchSecurityException(message.getFormattedMessage()));
    }

    private void logAndRespond(ParameterizedMessage message, Throwable e, ActionListener listener) {
        logger.debug(message.getFormattedMessage(), e);
        listener.onFailure(new ElasticsearchSecurityException(message.getFormattedMessage(), e));
    }
}
