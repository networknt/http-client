package com.networknt.http.client;

import com.networknt.http.client.ssl.TLSConfig;
import com.networknt.http.client.ssl.TlsUtil;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.security.*;
import java.time.Duration;
import java.util.Map;

public class HttpClientRequest {

    private  static Logger logger = LoggerFactory.getLogger(HttpClientRequest.class);
    private ClientConfig clientConfig;
    HttpClient httpClient;

    public static final String TLS = "tls";
    static final String LOAD_TRUST_STORE = "loadTrustStore";
    static final String LOAD_KEY_STORE = "loadKeyStore";
    static final String TRUST_STORE = "trustStore";
    static final String TRUST_STORE_PASS = "trustStorePass";
    static final String KEY_STORE = "keyStore";
    static final String KEY_STORE_PASS = "keyStorePass";
    static final String KEY_PASS = "keyPass";
    static final String KEY_STORE_PROPERTY = "javax.net.ssl.keyStore";
    static final String KEY_STORE_PASSWORD_PROPERTY = "javax.net.ssl.keyStorePassword";
    static final String TRUST_STORE_PROPERTY = "javax.net.ssl.trustStore";
    static final String TRUST_STORE_PASSWORD_PROPERTY = "javax.net.ssl.trustStorePassword";

    public HttpClientRequest() {
        clientConfig = ClientConfig.get();
        httpClient = buildHttpClient(clientConfig);
    }

    protected HttpClient buildHttpClient(ClientConfig clientConfig) {
        return HttpClient.newBuilder()
                .version(clientConfig.getHttpVersion())
                .connectTimeout(Duration.ofMillis(clientConfig.getTimeout()))
                .build();

    }



    /**
     * default method for creating ssl context. trustedNames config is not used.
     *
     * @return SSLContext
     * @throws IOException IOException
     */
    public static SSLContext createSSLContext() throws IOException {
        Map<String, Object> tlsMap = (Map<String, Object>)ClientConfig.get().getMappedConfig().get(TLS);

        return null==tlsMap?null:createSSLContext((String)tlsMap.get(TLSConfig.DEFAULT_GROUP_KEY));
    }

    /**
     * create ssl context using specified trustedName config
     *
     * @param trustedNamesGroupKey - the trustedName config to be used
     * @return SSLContext
     * @throws IOException IOException
     */
    @SuppressWarnings("unchecked")
    public static SSLContext createSSLContext(String trustedNamesGroupKey) throws IOException {
        SSLContext sslContext = null;
        KeyManager[] keyManagers = null;
        Map<String, Object> tlsMap = (Map<String, Object>)ClientConfig.get().getMappedConfig().get(TLS);
        if(tlsMap != null) {
            try {
                // load key store for client certificate if two way ssl is used.
                Boolean loadKeyStore = (Boolean) tlsMap.get(LOAD_KEY_STORE);
                if (loadKeyStore != null && loadKeyStore) {
                    String keyStoreName = System.getProperty(KEY_STORE_PROPERTY);
                    String keyStorePass = System.getProperty(KEY_STORE_PASSWORD_PROPERTY);
                    if (keyStoreName != null && keyStorePass != null) {
                        if(logger.isInfoEnabled()) logger.info("Loading key store from system property at " + Encode.forJava(keyStoreName));
                    } else {
                        keyStoreName = (String) tlsMap.get(KEY_STORE);
                        keyStorePass = (String) tlsMap.get(KEY_STORE_PASS);
                        if(keyStorePass == null) {
                            logger.error("Cann not load the config:" +  KEY_STORE_PASS + "from client.yml");
                        }
                        if(logger.isInfoEnabled()) logger.info("Loading key store from config at " + Encode.forJava(keyStoreName));
                    }
                    if (keyStoreName != null && keyStorePass != null) {
                        String keyPass = (String) tlsMap.get(KEY_PASS);
                        if(keyPass == null) {
                            logger.error("Can not load the config:"  + KEY_PASS, "client.yml");
                        }
                        KeyStore keyStore = TlsUtil.loadKeyStore(keyStoreName, keyStorePass.toCharArray());
                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                        keyManagerFactory.init(keyStore, keyPass.toCharArray());
                        keyManagers = keyManagerFactory.getKeyManagers();
                    }
                }
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
                throw new IOException("Unable to initialise KeyManager[]", e);
            }

            TrustManager[] trustManagers = null;
            try {
                // load trust store, this is the server public key certificate
                // first check if javax.net.ssl.trustStore system properties is set. It is only necessary if the server
                // certificate doesn't have the entire chain.
                Boolean loadTrustStore = (Boolean) tlsMap.get(LOAD_TRUST_STORE);
                if (loadTrustStore != null && loadTrustStore) {
                    String trustStoreName = System.getProperty(TRUST_STORE_PROPERTY);
                    String trustStorePass = System.getProperty(TRUST_STORE_PASSWORD_PROPERTY);
                    if (trustStoreName != null && trustStorePass != null) {
                        if(logger.isInfoEnabled()) logger.info("Loading trust store from system property at " + Encode.forJava(trustStoreName));
                    } else {
                        trustStoreName = (String) tlsMap.get(TRUST_STORE);
                        trustStorePass = (String) tlsMap.get(TRUST_STORE_PASS);
                        if(trustStorePass == null) {
                            logger.error("Can not load the config:"  + TRUST_STORE_PASS, "client.yml");
                        }
                        if(logger.isInfoEnabled()) logger.info("Loading trust store from config at " + Encode.forJava(trustStoreName));
                    }
                    if (trustStoreName != null && trustStorePass != null) {
                        KeyStore trustStore = TlsUtil.loadTrustStore(trustStoreName, trustStorePass.toCharArray());

                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(trustStore);
                        trustManagers = trustManagerFactory.getTrustManagers();
                    }
                }
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                throw new IOException("Unable to initialise TrustManager[]", e);
            }

            try {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(keyManagers, trustManagers, null);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new IOException("Unable to create and initialise the SSLContext", e);
            }
        } else {
            logger.error("TLS configuration section is missing in client.yml");
        }

        return sslContext;
    }


}
