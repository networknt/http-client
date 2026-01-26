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

import com.networknt.client.*;
import com.networknt.config.Config;
import com.networknt.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * The request that is used to get the key for token verification. It first check the token/key section in the
 * client.yml and then key section of token for backward compatibility. It is recommended to set the key under
 * token to clear indicate that the key is for token verification.
 *
 * @author Steve Hu
 */
public class TokenKeyRequest extends KeyRequest {
    private static final Logger logger = LoggerFactory.getLogger(TokenKeyRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";

    private boolean jwk;

    public TokenKeyRequest(String kid) {
        this(kid, false, null);
    }

    // this method is for multiple oauth servers.
    public TokenKeyRequest(String kid, boolean jwk, AuthServerConfig authServerConfig) {
        super(kid);
        this.jwk = jwk;
        ClientConfig clientConfig = ClientConfig.get();
        if(clientConfig != null) {
            OAuthConfig oauthConfig = clientConfig.getOAuth();
            if(oauthConfig != null) {
                // there is no key section under oauth. look up in the oauth/token section for key
                OAuthTokenConfig tokenConfig = oauthConfig.getToken();
                if(tokenConfig != null) {
                    // first inherit the proxy config from the token config.
                    setProxyHost(tokenConfig.getProxyHost());
                    int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
                    setProxyPort(port);
                    if(authServerConfig == null) {
                        // this is the single oauth configuration, get the key config.
                        OAuthTokenKeyConfig keyConfig = tokenConfig.getKey();
                        if(keyConfig != null) {
                            setAuthServerConfig(keyConfig);
                        } else {
                            logger.error(new Status(CONFIG_PROPERTY_MISSING, "token key section", "client.yml").toString());
                        }
                    } else {
                        // this is the multiple oauth configuration and the passed in authServerConfig is not empty.
                        setAuthServerConfig(authServerConfig);
                    }
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "token section", "client.yml").toString());
                }
            } else {
                logger.error(new Status(CONFIG_PROPERTY_MISSING, "oauth section", "client.yml").toString());
            }
        } else {
            logger.error(new Status(CONFIG_PROPERTY_MISSING, "oauth key section", "client.yml").toString());
        }
    }

    private void setAuthServerConfig(AuthServerConfig authServerConfig) {
        setServerUrl(authServerConfig.getServerUrl());
        setEnableHttp2(authServerConfig.isEnableHttp2());
        if(jwk) {
            // there is no additional kid in the path parameter for jwk
            setUri(authServerConfig.getUri());
        } else {
            setUri(authServerConfig.getUri() + "/" + kid);
        }
        // clientId is optional
        if(authServerConfig.getClientId() != null) {
            setClientId(String.valueOf(authServerConfig.getClientId()));
        }
        // clientSecret is optional
        if(authServerConfig.getClientSecret() != null) {
            setClientSecret(String.valueOf(authServerConfig.getClientSecret()));
        }
        // audience is optional
        if(authServerConfig.getAudience() != null) {
            setAudience(authServerConfig.getAudience());
        }
    }

    private void setAuthServerConfig(OAuthTokenKeyConfig keyConfig) {
        setServerUrl(keyConfig.getServerUrl());
        setServiceId(keyConfig.getServiceId());
        setEnableHttp2(keyConfig.isEnableHttp2());
        if(jwk) {
            // there is no additional kid in the path parameter for jwk
            setUri(keyConfig.getUri());
        } else {
            setUri(keyConfig.getUri() + "/" + kid);
        }
        // clientId is optional
        if(keyConfig.getClientId() != null) {
            setClientId(String.valueOf(keyConfig.getClientId()));
        }
        // clientSecret is optional
        if(keyConfig.getClientSecret() != null) {
            setClientSecret(String.valueOf(keyConfig.getClientSecret()));
        }
        // audience is optional
        if(keyConfig.getAudience() != null) {
            setAudience(keyConfig.getAudience());
        }
    }

}
