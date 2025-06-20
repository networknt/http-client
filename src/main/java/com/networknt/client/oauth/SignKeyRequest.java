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
import com.networknt.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * The configuration is coming from the sign/key section in the client.yml file. This request is used
 * to get the key for sign verification. The proxy configuration is defined in the sign section as it
 * is not possible the same service using two different proxy servers.
 *
 * @author Steve Hu
 */
public class SignKeyRequest extends KeyRequest {
    private static Logger logger = LoggerFactory.getLogger(SignKeyRequest.class);

    @Deprecated
    public static String SIGN = "sign";

    public SignKeyRequest(String kid) {
        super(kid);

        Map<String, Object> signConfig = ClientConfig.get().getSignConfig();
        if(signConfig != null) {
            Map<String, Object> keyConfig = (Map<String, Object>)signConfig.get(ClientConfig.KEY);
            if(keyConfig != null) {
                setServerUrl((String)keyConfig.get(ClientConfig.SERVER_URL));
                setProxyHost((String)signConfig.get(ClientConfig.PROXY_HOST));
                int port = signConfig.get(ClientConfig.PROXY_PORT) == null ? 443 : Config.loadIntegerValue(ClientConfig.PROXY_PORT, signConfig.get(ClientConfig.PROXY_PORT));
                setProxyPort(port);
                setServiceId((String)keyConfig.get(ClientConfig.SERVICE_ID));
                Object object = keyConfig.get(ClientConfig.ENABLE_HTTP2);
                if(object != null) setEnableHttp2(Config.loadBooleanValue(ClientConfig.ENABLE_HTTP2, object));
                setUri(keyConfig.get(ClientConfig.URI) + "/" + kid);
                setClientId((String)keyConfig.get(ClientConfig.CLIENT_ID));
                setClientSecret((String)keyConfig.get(ClientConfig.CLIENT_SECRET));
                // audience is optional
                if(keyConfig.get(ClientConfig.AUDIENCE) != null) {
                    setAudience((String)keyConfig.get(ClientConfig.AUDIENCE));
                }
            } else {
                logger.error("Error: could not find key section in sign of oauth in client.yml");
            }
        } else {
            logger.error("Error: could not find sign section of oauth in client.yml");
        }
    }
}
