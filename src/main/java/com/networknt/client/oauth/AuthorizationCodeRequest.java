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

import com.fasterxml.jackson.core.type.TypeReference;
import com.networknt.client.ClientConfig;
import com.networknt.client.OAuthTokenAuthorizationCodeConfig;
import com.networknt.client.OAuthTokenConfig;
import com.networknt.config.Config;
import com.networknt.config.ConfigException;
import com.networknt.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Created by steve on 02/09/16.
 */
public class AuthorizationCodeRequest extends TokenRequest {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";
    private String authCode;
    private String redirectUri;
    /**
     * load default values from client.json for authorization code grant, overwrite by setters
     * in case you want to change it at runtime.
     */
    public AuthorizationCodeRequest() {
        setGrantType(ClientConfig.AUTHORIZATION_CODE);
        OAuthTokenConfig tokenConfig = ClientConfig.get().getOAuth().getToken();
        if(tokenConfig != null) {
            setServerUrl(tokenConfig.getServerUrl());
            setProxyHost(tokenConfig.getProxyHost());
            int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
            setProxyPort(port);
            setServiceId(tokenConfig.getServiceId());
            setEnableHttp2(tokenConfig.isEnableHttp2());
            OAuthTokenAuthorizationCodeConfig acConfig = tokenConfig.getAuthorizationCode();
            if(acConfig != null) {
                setClientId(String.valueOf(acConfig.getClientId()));
                if(acConfig.getClientSecret() != null) {
                    setClientSecret(String.valueOf(acConfig.getClientSecret()));
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "authorization_code client_secret", "client.yml").toString());
                }
                setUri(acConfig.getUri());
                setScope(acConfig.getScope());
                setRedirectUri(acConfig.getRedirectUri());
            }
        }
    }

    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

}
