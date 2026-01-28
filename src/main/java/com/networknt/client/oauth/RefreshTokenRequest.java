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
import com.networknt.client.OAuthTokenConfig;
import com.networknt.client.OAuthTokenRefreshTokenConfig;
import com.networknt.config.Config;
import com.networknt.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class RefreshTokenRequest extends TokenRequest {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";

    String refreshToken;

    public RefreshTokenRequest() {
        setGrantType(ClientConfig.REFRESH_TOKEN);
        OAuthTokenConfig tokenConfig = ClientConfig.get().getOAuth().getToken();
        if(tokenConfig != null) {
            setServerUrl(tokenConfig.getServerUrl());
            setProxyHost(tokenConfig.getProxyHost());
            int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
            setProxyPort(port);
            setServiceId(tokenConfig.getServiceId());
            setEnableHttp2(tokenConfig.isEnableHttp2());
            OAuthTokenRefreshTokenConfig rtConfig = tokenConfig.getRefreshToken();
            if(rtConfig != null) {
                setClientId(String.valueOf(rtConfig.getClientId()));
                if(rtConfig.getClientSecret() != null) {
                    setClientSecret(String.valueOf(rtConfig.getClientSecret()));
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "refresh_token client_secret", "client.yml").toString());
                }
                setUri(rtConfig.getUri());
                setScope(rtConfig.getScope());
            }
        }
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
