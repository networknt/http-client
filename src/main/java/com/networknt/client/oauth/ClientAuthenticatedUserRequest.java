package com.networknt.client.oauth;

import com.networknt.client.ClientConfig;
import com.networknt.client.OAuthTokenAuthorizationCodeConfig;
import com.networknt.client.OAuthTokenConfig;
import com.networknt.config.Config;
import com.networknt.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ClientAuthenticatedUserRequest extends TokenRequest {
    private static final Logger logger = LoggerFactory.getLogger(ClientAuthenticatedUserRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";
    private String userType;
    private String userId;
    private String roles;
    private String redirectUri;

    /**
     * load default values from client.yml for client authenticated user grant, overwrite by setters
     * in case you want to change it at runtime.
     * @param userType user type
     * @param userId user id
     * @param roles user roles
     */
    public ClientAuthenticatedUserRequest(String userType, String userId, String roles) {
        setGrantType(ClientConfig.CLIENT_AUTHENTICATED_USER);
        setUserType(userType);
        setUserId(userId);
        setRoles(roles);
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
                setRedirectUri((String)acConfig.getRedirectUri());
            }
        }
    }

    public String getUserType() {
        return userType;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

}
