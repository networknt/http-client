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

package com.networknt.http.client;

import com.networknt.http.client.monad.Status;
import com.networknt.http.client.oauth.TokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        setGrantType(ClientConfig.CLIENT_CREDENTIALS);
        Map<String, Object> tokenConfig = ClientConfig.get().getTokenConfig();
        if(tokenConfig != null) {
            setServerUrl((String)tokenConfig.get(ClientConfig.SERVER_URL));
            setProxyHost((String)tokenConfig.get(ClientConfig.PROXY_HOST));
            int port = tokenConfig.get(ClientConfig.PROXY_PORT) == null ? 443 : (Integer)tokenConfig.get(ClientConfig.PROXY_PORT);
            setProxyPort(port);
            setServiceId((String)tokenConfig.get(ClientConfig.SERVICE_ID));
            Object object = tokenConfig.get(ClientConfig.ENABLE_HTTP2);
            setEnableHttp2(object != null && (Boolean) object);
            Map<String, Object> ccConfig = (Map<String, Object>) tokenConfig.get(ClientConfig.CLIENT_CREDENTIALS);
            if(ccConfig != null) {
                setClientId((String)ccConfig.get(ClientConfig.CLIENT_ID));
                if(ccConfig.get(ClientConfig.CLIENT_SECRET) != null) {
                    setClientSecret((String)ccConfig.get(ClientConfig.CLIENT_SECRET));
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "client_credentials client_secret in client.yml").toString());
                }
                setUri((String)ccConfig.get(ClientConfig.URI));
                //set default scope from config.
                setScope((List<String>)ccConfig.get(ClientConfig.SCOPE));
            }
        }
    }
}
