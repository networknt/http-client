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

package com.networknt.http.client.oauth;


import com.networknt.http.client.ClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * This holds values used to call the SAML Bearer grant flow from the OAuth Server.
 * In this version client presents a SAML token and a JWT token.
 *
 * @author David G.
 */
public class SAMLBearerRequest extends TokenRequest {

    // x-www-urlencoded keys / values sent to OAuth server for SAML grant flow
    public static final String CLIENT_ASSERTION_TYPE_KEY = "client_assertion_type";
    public static final String CLIENT_ASSERTION_TYPE_VALUE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String CLIENT_ASSERTION_KEY = "client_assertion"; // value is JWT
    public static final String ASSERTION_KEY = "assertion"; // value is SAML token
    public static final String GRANT_TYPE_KEY = "grant_type";
    public static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:saml2-bearer";

    private String samlAssertion;
    private String jwtClientAssertion;
    private static final Logger logger = LoggerFactory.getLogger(SAMLBearerRequest.class);

    public SAMLBearerRequest(String samlAssertion, String jwtClientAssertion) {

        setGrantType(ClientConfig.SAML_BEARER);
        this.samlAssertion = samlAssertion;
        this.jwtClientAssertion = jwtClientAssertion;

        try {
            ClientConfig clientConfig = ClientConfig.load();
            Map<String, Object> tokenConfig = clientConfig.getTokenConfig();
            setServerUrl((String)tokenConfig.get(ClientConfig.SERVER_URL));
            setProxyHost((String)tokenConfig.get(ClientConfig.PROXY_HOST));
            int port = tokenConfig.get(ClientConfig.PROXY_PORT) == null ? 443 : (Integer)tokenConfig.get(ClientConfig.PROXY_PORT);
            setProxyPort(port);
            Object object = tokenConfig.get(ClientConfig.ENABLE_HTTP2);
            setEnableHttp2(object != null && (Boolean) object);
            Map<String, Object> ccConfig = (Map<String, Object>) tokenConfig.get(ClientConfig.CLIENT_CREDENTIALS);

            setClientId((String) ccConfig.get(ClientConfig.CLIENT_ID));
            setUri((String) ccConfig.get(ClientConfig.URI));
        } catch (NullPointerException e) {
            logger.error("Nullpointer in config object: " + e);
        }
    }


    public String getSamlAssertion() {
        return this.samlAssertion;
    }

    public String getJwtClientAssertion() {
        return this.jwtClientAssertion;
    }
}