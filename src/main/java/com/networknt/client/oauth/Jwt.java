/*
 * Copyright (c) 2019 Network New Technologies Inc.
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
import com.networknt.utility.StringUtils;

import java.util.*;

/**
 * a model class represents a JWT mostly for caching usage so that we don't need to decrypt jwt string to get info.
 * it will load config from client.yml/oauth/token
 */
public class Jwt {

    protected String scopes;
    protected Key key;
    /**
     * This is the client credentials token config if multiple auth servers are used.
     */
    protected Map<String, Object> ccConfig;

    /**
     * the cached jwt token for client credentials grant type
     */
    private String jwt;

    /**
     * jwt expire time in millisecond so that we don't need to parse the jwt.
     */
    private long expire;
    private volatile boolean renewing = false;
    private volatile long expiredRetryTimeout;
    private volatile long earlyRetryTimeout;
    private static long tokenRenewBeforeExpired;
    private static long expiredRefreshRetryDelay;
    private static long earlyRefreshRetryDelay;

    public Jwt() {
        Map<String, Object> tokenConfig = ClientConfig.get().getTokenConfig();
        if(tokenConfig != null) {
            Object object = tokenConfig.get(ClientConfig.TOKEN_RENEW_BEFORE_EXPIRED);
            if(object != null) tokenRenewBeforeExpired = Config.loadLongValue(ClientConfig.TOKEN_RENEW_BEFORE_EXPIRED, object);
            object = tokenConfig.get(ClientConfig.EXPIRED_REFRESH_RETRY_DELAY);
            if(object != null) expiredRefreshRetryDelay = Config.loadLongValue(ClientConfig.EXPIRED_REFRESH_RETRY_DELAY, object);
            object = tokenConfig.get(ClientConfig.EARLY_REFRESH_RETRY_DELAY);
            if(object != null) earlyRefreshRetryDelay = Config.loadLongValue(ClientConfig.EARLY_REFRESH_RETRY_DELAY, object);
        }
    }

    public Jwt(Key key) {
        this();
        this.key = key;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public long getExpire() {
        return expire;
    }

    public void setExpire(long expire) {
        this.expire = expire;
    }

    public boolean isRenewing() {
        return renewing;
    }

    public void setRenewing(boolean renewing) {
        this.renewing = renewing;
    }

    public long getExpiredRetryTimeout() {
        return expiredRetryTimeout;
    }

    public void setExpiredRetryTimeout(long expiredRetryTimeout) {
        this.expiredRetryTimeout = expiredRetryTimeout;
    }

    public long getEarlyRetryTimeout() {
        return earlyRetryTimeout;
    }

    public void setEarlyRetryTimeout(long earlyRetryTimeout) {
        this.earlyRetryTimeout = earlyRetryTimeout;
    }

    public static long getTokenRenewBeforeExpired() {
        return tokenRenewBeforeExpired;
    }

    public static void setTokenRenewBeforeExpired(long tokenRenewBeforeExpired) {
        Jwt.tokenRenewBeforeExpired = tokenRenewBeforeExpired;
    }

    public static long getExpiredRefreshRetryDelay() {
        return expiredRefreshRetryDelay;
    }

    public static void setExpiredRefreshRetryDelay(long expiredRefreshRetryDelay) {
        Jwt.expiredRefreshRetryDelay = expiredRefreshRetryDelay;
    }

    public static long getEarlyRefreshRetryDelay() {
        return earlyRefreshRetryDelay;
    }

    public static void setEarlyRefreshRetryDelay(long earlyRefreshRetryDelay) {
        Jwt.earlyRefreshRetryDelay = earlyRefreshRetryDelay;
    }

    public Map<String, Object> getCcConfig() {
        return ccConfig;
    }

    public void setCcConfig(Map<String, Object> ccConfig) {
        this.ccConfig = ccConfig;
    }

    public Set<String> getScopesSet() {
        Set<String> scopesSet = new HashSet<>();
        if(StringUtils.isBlank(scopes)) return scopesSet;
        scopesSet.addAll(Arrays.asList(scopes.split("(\\s)+")));
        return scopesSet;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public Key getKey() {
        return key;
    }

    /**
     * an inner model tight to Jwt, this key is to represent to a Jwt for caching or other usage
     * for now it's only identified by scopes and serviceId combination or one of them.
     */
    public static class Key {
        /**
         * scopes should be extendable by its children
         */
        protected String scopes;
        /**
         * serviceId should be extendable by its children
         */
        protected String serviceId;

        @Override
        public int hashCode() {
            return Objects.hash(scopes, serviceId);
        }

        @Override
        public boolean equals(Object obj) {
            return hashCode() == obj.hashCode();
        }

        public Key(String serviceId, String scopes) {
            this.serviceId = serviceId;
            this.scopes = scopes;
        }

        public Key(String serviceId) {
            this.serviceId = serviceId;
        }

        public Key() {

        }

        public String getScopes() {
            return scopes;
        }

        public Set<String> getScopesSet() {
            Set<String> scopesSet = new HashSet<>();
            if(StringUtils.isBlank(scopes)) return scopesSet;
            scopesSet.addAll(Arrays.asList(scopes.split("(\\s)+")));
            return scopesSet;
        }

        public void setScopes(String scopes) {
            this.scopes = scopes;
        }

        public void setServiceId(String serviceId) {
            this.serviceId = serviceId;
        }

        public String getServiceId() {
            return serviceId;
        }
    }
}
