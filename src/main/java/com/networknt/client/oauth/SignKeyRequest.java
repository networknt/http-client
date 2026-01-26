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
import com.networknt.client.OAuthSignConfig;
import com.networknt.client.OAuthSignKeyConfig;
import com.networknt.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * The configuration is coming from the sign/key section in the client.yml file. This request is used
 * to get the key for sign verification. The proxy configuration is defined in the sign section as it
 * is not possible the same service using two different proxy servers.
 *
 * @author Steve Hu
 */
public class SignKeyRequest extends KeyRequest {
    private static final Logger logger = LoggerFactory.getLogger(SignKeyRequest.class);

    @Deprecated
    public static String SIGN = "sign";

    public SignKeyRequest(String kid) {
        super(kid);

        OAuthSignConfig signConfig = ClientConfig.get().getOAuth().getSign();
        if(signConfig != null) {
            OAuthSignKeyConfig keyConfig = signConfig.getKey();
            if(keyConfig != null) {
                setServerUrl(keyConfig.getServerUrl());
                setProxyHost(signConfig.getProxyHost());
                int port = signConfig.getProxyPort() == null ? 443 : signConfig.getProxyPort();
                setProxyPort(port);
                setServiceId(keyConfig.getServiceId());
                setEnableHttp2(keyConfig.isEnableHttp2());
                setUri(keyConfig.getUri() + "/" + kid);
                setClientId(String.valueOf(keyConfig.getClientId()));
                setClientSecret(String.valueOf(keyConfig.getClientSecret()));
                // audience is optional
                if(keyConfig.getAudience() != null) {
                    setAudience(keyConfig.getAudience());
                }
            } else {
                logger.error("Error: could not find key section in sign of oauth in client.yml");
            }
        } else {
            logger.error("Error: could not find sign section of oauth in client.yml");
        }
    }
}
