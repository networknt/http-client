package com.networknt.client.oauth;

import com.networknt.client.*;
import com.networknt.config.Config;
import com.networknt.status.Status;
import com.networknt.utility.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * The request that is used to post the introspection request to verify the simple web token. It first checks
 * the token/key section in the client.yml and then key section of token for backward compatibility. It is
 * recommended to set the key/introspection under token to clear indicate that the introspection is for token
 * verification.
 *
 * @author Steve Hu
 */
public class TokenIntrospectionRequest extends IntrospectionRequest {
    private static final Logger logger = LoggerFactory.getLogger(TokenIntrospectionRequest.class);
    private static final String CONFIG_PROPERTY_MISSING = "ERR10057";

    public TokenIntrospectionRequest(String swt) {
        this(swt, null);
    }
    public TokenIntrospectionRequest(String swt, AuthServerConfig authServerConfig) {
        super(swt);
        ClientConfig clientConfig = ClientConfig.get();
        if(clientConfig != null) {
            OAuthConfig oauthConfig = clientConfig.getOAuth();
            if(oauthConfig != null) {
                // there is no key section under oauth. look up in the oauth/token section for introspection
                OAuthTokenConfig tokenConfig = oauthConfig.getToken();
                if(tokenConfig != null) {
                    // first inherit the proxy config from the token config.
                    setProxyHost(tokenConfig.getProxyHost());
                    int port = tokenConfig.getProxyPort() == null ? 443 : tokenConfig.getProxyPort();
                    setProxyPort(port);
                    // set the default values from the key section of token for single auth server.
                    OAuthTokenKeyConfig keyConfig = tokenConfig.getKey();
                    if(keyConfig != null) {
                        setIntrospectionOptions(keyConfig);
                    } else {
                        logger.error(new Status(CONFIG_PROPERTY_MISSING, "key section", "client.yml").toString());
                    }
                    if(authServerConfig != null) {
                        // overwrite the default values with the values from the passed in config.
                        setIntrospectionOptions(authServerConfig);
                    }
                } else {
                    logger.error(new Status(CONFIG_PROPERTY_MISSING, "token section", "client.yml").toString());
                }
            } else {
                logger.error(new Status(CONFIG_PROPERTY_MISSING, "oauth section", "client.yml").toString());
            }
        } else {
            logger.error(new Status(CONFIG_PROPERTY_MISSING, "client section", "client.yml").toString());
        }
    }

    private void setIntrospectionOptions(AuthServerConfig authServerConfig) {
        if(logger.isTraceEnabled()) logger.trace("Overwrite Introspection with authServerConfig {}", authServerConfig);

        if(authServerConfig.getServerUrl() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old serverUrl {} with new serverUrl {}", getServerUrl(), authServerConfig.getServerUrl());
            setServerUrl(authServerConfig.getServerUrl());
        }
        if(authServerConfig.isEnableHttp2() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old enableHttp2 {} with new enableHttp2 {}", isEnableHttp2(), authServerConfig.isEnableHttp2());
            setEnableHttp2(authServerConfig.isEnableHttp2());
        }
        if(authServerConfig.getUri() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old uri {} with new uri {}", getUri(), authServerConfig.getUri());
            setUri(authServerConfig.getUri());
        }

        // clientId is optional
        if(authServerConfig.getClientId() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old clientId {} with new clientId {}", getClientId(), authServerConfig.getClientId());
            setClientId(String.valueOf(authServerConfig.getClientId()));
        }
        // clientSecret is optional
        if(authServerConfig.getClientSecret() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old clientSecret {} with new clientSecret {}", StringUtils.maskHalfString(getClientSecret()), StringUtils.maskHalfString(String.valueOf(authServerConfig.getClientSecret())));
            setClientSecret(String.valueOf(authServerConfig.getClientSecret()));
        }
        // proxyHost and proxyPort are optional to overwrite the token config inherited.
        if(authServerConfig.getProxyHost() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old proxyHost {} with new proxyHost {}", getProxyHost(), authServerConfig.getProxyHost());
            String proxyHost = authServerConfig.getProxyHost();
            if(proxyHost.length() > 1) {
                // overwrite the tokenConfig proxyHost and proxyPort if this particular service has different proxy server
                setProxyHost(proxyHost);
                int port = authServerConfig.getProxyPort() == null ? 443 : authServerConfig.getProxyPort();
                setProxyPort(port);
            } else {
                // if this service doesn't need a proxy server, just use an empty string to remove the tokenConfig proxy host.
                setProxyHost(null);
                setProxyPort(0);
            }
        }
    }

    private void setIntrospectionOptions(OAuthTokenKeyConfig keyConfig) {
        if(logger.isTraceEnabled()) logger.trace("Overwrite Introspection with keyConfig {}", keyConfig);
        if(keyConfig.getServerUrl() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old serverUrl {} with new serverUrl {}", getServerUrl(), keyConfig.getServerUrl());
            setServerUrl(keyConfig.getServerUrl());
        }
        if(keyConfig.getServiceId() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old serviceId {} with new serviceId {}", getServiceId(), keyConfig.getServiceId());
            setServiceId(keyConfig.getServiceId());
        }
        if(keyConfig.isEnableHttp2() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old enableHttp2 {} with new enableHttp2 {}", isEnableHttp2(), keyConfig.isEnableHttp2());
            setEnableHttp2(keyConfig.isEnableHttp2());
        }
        if(keyConfig.getUri() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old uri {} with new uri {}", getUri(), keyConfig.getUri());
            setUri(keyConfig.getUri());
        }

        // clientId is optional
        if(keyConfig.getClientId() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old clientId {} with new clientId {}", getClientId(), keyConfig.getClientId());
            setClientId(String.valueOf(keyConfig.getClientId()));
        }
        // clientSecret is optional
        if(keyConfig.getClientSecret() != null) {
            if(logger.isTraceEnabled()) logger.trace("overwrite old clientSecret {} with new clientSecret {}", StringUtils.maskHalfString(getClientSecret()), StringUtils.maskHalfString(String.valueOf(keyConfig.getClientSecret())));
            setClientSecret(String.valueOf(keyConfig.getClientSecret()));
        }
    }

}
