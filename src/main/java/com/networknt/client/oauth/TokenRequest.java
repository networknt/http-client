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
import com.networknt.config.Config;
import com.networknt.config.ConfigException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Created by steve on 02/09/16.
 */
public class TokenRequest {
    private String grantType;
    private String serverUrl;
    private String proxyHost;
    private int proxyPort;
    private String serviceId;
    private boolean enableHttp2;
    private String uri;
    private String clientId;
    private String clientSecret;
    private List<String> scope;
    /**
     * put csrf here as both authorization code and refresh token need it.
     */
    private String csrf;

    public TokenRequest() {
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getUri() {
        return uri;
    }

    public boolean isEnableHttp2() { return enableHttp2; }

    public void setEnableHttp2(boolean enableHttp2) { this.enableHttp2 = enableHttp2; }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getServiceId() {
        return serviceId;
    }

    public void setServiceId(String serviceId) {
        this.serviceId = serviceId;
    }

    public String getCsrf() { return csrf; }

    public void setCsrf(String csrf) { this.csrf = csrf; }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    List<String> loadScope(Map<String, Object> acConfig) {
        List<String> list = null;
        if(acConfig != null && acConfig.get(ClientConfig.SCOPE) != null) {
            Object object = acConfig.get(ClientConfig.SCOPE);
            list = new ArrayList<>();
            if(object instanceof String) {
                String s = (String)object;
                s = s.trim();
                if(s.startsWith("[")) {
                    // json format
                    try {
                        list = Config.getInstance().getMapper().readValue(s, new TypeReference<List<String>>() {
                        });
                    } catch (Exception e) {
                        throw new ConfigException("could not parse the scope json with a list of string.");
                    }
                } else {
                    // comma separated
                    list = Arrays.asList(s.split("\\s*,\\s*"));
                }
            } else if(object instanceof List) {
                list = (List<String>)object;
            } else {
                throw new ConfigException("scope must be a list of strings.");
            }
        }
        return list;
    }

}
