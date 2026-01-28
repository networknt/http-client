/*
 * Copyright (c) 2016 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.networknt.client.oauth;


import com.networknt.client.ClientConfig;
import com.networknt.client.OAuthTokenClientCredentialConfig;
import com.networknt.client.OAuthTokenConfig;
import com.networknt.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * This holds values used to call the SAML Bearer grant flow from the OAuth Server.
 * In this version client presents a SAML token and a JWT token.
 *
 * @author David G.
 */
public class SAMLBearerRequest extends TokenRequest {

    // x-www-urlencoded keys / values sent to OAuth server for SAML grant flow
    static final String CLIENT_ASSERTION_TYPE_KEY = "client_assertion_type";
    static final String CLIENT_ASSERTION_TYPE_VALUE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final String CLIENT_ASSERTION_KEY = "client_assertion"; // value is JWT
    static final String ASSERTION_KEY = "assertion"; // value is SAML token
    static final String GRANT_TYPE_KEY = "grant_type";
    static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:saml2-bearer";

    private final String samlAssertion;
    private final String jwtClientAssertion;
    private static final Logger logger = LoggerFactory.getLogger(SAMLBearerRequest.class);

    public SAMLBearerRequest(String samlAssertion, String jwtClientAssertion) {

        setGrantType(ClientConfig.SAML_BEARER);
        this.samlAssertion = samlAssertion;
        this.jwtClientAssertion = jwtClientAssertion;

        try {
            OAuthTokenConfig tokenConfig = ClientConfig.get().getOAuth().getToken();

            setServerUrl(tokenConfig.getServerUrl());
            setProxyHost(tokenConfig.getProxyHost());
            int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
            setProxyPort(port);
            setEnableHttp2(tokenConfig.isEnableHttp2());
            OAuthTokenClientCredentialConfig ccConfig = tokenConfig.getClientCredentials();

            setClientId(String.valueOf(ccConfig.getClientId()));
            setUri(ccConfig.getUri());
        } catch (NullPointerException e) {
            logger.error("Exception:", e);
        }
    }


    public String getSamlAssertion() {
        return this.samlAssertion;
    }

    public String getJwtClientAssertion() {
        return this.jwtClientAssertion;
    }
}
