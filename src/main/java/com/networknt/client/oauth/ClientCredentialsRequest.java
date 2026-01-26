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
import java.util.List;
import java.util.Map;

/**
 * load default values from client.yml for client credentials grant, overwrite by setters
 * in case you want to change it at runtime.
 *
 * @author Steve Hu
 */
public class ClientCredentialsRequest extends TokenRequest {
    private static final Logger logger = LoggerFactory.getLogger(ClientCredentialsRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";
    public ClientCredentialsRequest() {
        this(null);
    }

    public ClientCredentialsRequest(AuthServerConfig authServerConfig) {
        setGrantType(ClientConfig.CLIENT_CREDENTIALS);
        OAuthTokenConfig tokenConfig = ClientConfig.get().getOAuth().getToken();
        if(tokenConfig != null) {
            setServerUrl(tokenConfig.getServerUrl());
            setProxyHost(tokenConfig.getProxyHost());
            int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
            setProxyPort(port);
            setServiceId(tokenConfig.getServiceId());
            setEnableHttp2(tokenConfig.isEnableHttp2());
            if(authServerConfig != null) {
                // populate details from the authServerConfig which is coming from the multiple oauth server config.

                if(authServerConfig.getClientId() != null) setClientId(String.valueOf(authServerConfig.getClientId()));
                if(authServerConfig.getClientSecret() != null) {
                    setClientSecret(String.valueOf(authServerConfig.getClientSecret()));
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "client_credentials client_secret", "client.yml").toString());
                }
                setUri(authServerConfig.getUri());
                //set default scope from config.
                setScope(authServerConfig.getScope());
                // overwrite server url, id, proxy host, id and http2 flag if they are defined in the ccConfig.
                // This is only used by the multiple auth servers. There is no reason to overwrite in single auth server.
                if(authServerConfig.getServerUrl() != null) {
                    setServerUrl(authServerConfig.getServerUrl());
                }
                if(authServerConfig.getProxyHost() != null) {
                    // give a chance to set proxyHost to null if a service doesn't need proxy.
                    String proxyHost = authServerConfig.getProxyHost();
                    if(proxyHost.length() > 1) {
                        setProxyHost(authServerConfig.getProxyHost());
                        port = authServerConfig.getProxyPort() == null ? 443 : authServerConfig.getProxyPort();
                        setProxyPort(port);
                    } else {
                        // overwrite the inherited proxyHost from the tokenConfig.
                        setProxyHost(null);
                        setProxyPort(0);
                    }
                }
                setEnableHttp2(authServerConfig.isEnableHttp2());
            } else {
                // this is a single oauth server configuration, populate extra info from the client credentials section.
                OAuthTokenClientCredentialConfig clientCredentialConfig = tokenConfig.getClientCredentials();
                if(clientCredentialConfig != null) {

                    if(clientCredentialConfig.getClientId() != null) setClientId(String.valueOf(clientCredentialConfig.getClientId()));
                    if(clientCredentialConfig.getClientSecret() != null) {
                        setClientSecret(String.valueOf(clientCredentialConfig.getClientSecret()));
                    } else {
                        logger.error(new Status(CONFIG_PROPERTY_MISSING, "client_credentials client_secret", "client.yml").toString());
                    }
                    setUri(clientCredentialConfig.getUri());
                    //set default scope from config.
                    setScope(clientCredentialConfig.getScope());
                }
            }
        }
    }
}
