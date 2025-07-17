package com.networknt.client.oauth;

import com.networknt.client.ClientConfig;
import com.networknt.config.Config;
import com.networknt.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class TokenExchangeRequest extends TokenRequest {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    /**
     * OPTIONAL. A URI that indicates the target service or resource where the
     * client intends to use the requested security token.
     */
    private String resource;

    /**
     * OPTIONAL. The logical name of the target service where the client intends
     * to use the requested security token.
     */
    private String audience;

    /**
     * OPTIONAL. An identifier for the type of the requested security token.
     * For example, "urn:ietf:params:oauth:token-type:access_token".
     */
    private String requestedTokenType;

    /**
     * REQUIRED. A security token that represents the identity of the party on
     * behalf of whom the request is being made.
     */
    private String subjectToken;

    /**
     * REQUIRED. An identifier for the type of the security token in the
     * "subject_token" parameter.
     * For example, "urn:ietf:params:oauth:token-type:jwt".
     */
    private String subjectTokenType;

    /**
     * OPTIONAL. A security token that represents the identity of the acting
     * party.
     */
    private String actorToken;

    /**
     * OPTIONAL. An identifier for the type of the security token in the
     * "actor_token" parameter.
     */
    private String actorTokenType;

    public TokenExchangeRequest() {
        setGrantType(TOKEN_EXCHANGE);
        Map<String, Object> tokenConfig = ClientConfig.get().getTokenConfig();
        if(tokenConfig != null) {
            setServerUrl((String)tokenConfig.get(ClientConfig.SERVER_URL));
            setProxyHost((String)tokenConfig.get(ClientConfig.PROXY_HOST));
            int port = tokenConfig.get(ClientConfig.PROXY_PORT) == null ? 443 : Config.loadIntegerValue(ClientConfig.PROXY_PORT, tokenConfig.get(ClientConfig.PROXY_PORT));
            setProxyPort(port);
            setServiceId((String)tokenConfig.get(ClientConfig.SERVICE_ID));
            Object object = tokenConfig.get(ClientConfig.ENABLE_HTTP2);
            if(object != null) setEnableHttp2(Config.loadBooleanValue(ClientConfig.ENABLE_HTTP2, object));
            Map<String, Object> exConfig = (Map<String, Object>) tokenConfig.get(ClientConfig.TOKEN_EXCHANGE);
            if(exConfig != null) {
                setClientId((String)exConfig.get(ClientConfig.CLIENT_ID));
                if(exConfig.get(ClientConfig.CLIENT_SECRET) != null) {
                    setClientSecret((String)exConfig.get(ClientConfig.CLIENT_SECRET));
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "token_exchange client_secret", "client.yml").toString());
                }
                setUri((String)exConfig.get(ClientConfig.URI));
                setScope(loadScope(exConfig));
                setSubjectToken((String)exConfig.get(ClientConfig.SUBJECT_TOKEN));
                setSubjectTokenType((String)exConfig.get(ClientConfig.SUBJECT_TOKEN_TYPE));
            }
        }
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getRequestedTokenType() {
        return requestedTokenType;
    }

    public void setRequestedTokenType(String requestedTokenType) {
        this.requestedTokenType = requestedTokenType;
    }

    public String getSubjectToken() {
        return subjectToken;
    }

    public void setSubjectToken(String subjectToken) {
        this.subjectToken = subjectToken;
    }

    public String getSubjectTokenType() {
        return subjectTokenType;
    }

    public void setSubjectTokenType(String subjectTokenType) {
        this.subjectTokenType = subjectTokenType;
    }

    public String getActorToken() {
        return actorToken;
    }

    public void setActorToken(String actorToken) {
        this.actorToken = actorToken;
    }

    public String getActorTokenType() {
        return actorTokenType;
    }

    public void setActorTokenType(String actorTokenType) {
        this.actorTokenType = actorTokenType;
    }
}
