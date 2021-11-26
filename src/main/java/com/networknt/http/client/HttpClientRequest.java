package com.networknt.http.client;

import com.networknt.http.client.ssl.TLSConfig;
import com.networknt.http.client.ssl.TlsUtil;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class HttpClientRequest {

    private  static Logger logger = LoggerFactory.getLogger(HttpClientRequest.class);
    private ClientConfig clientConfig;
    HttpClient httpClient;
    private  HttpRequest.Builder builder;

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

    public HttpResponse<?> send(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler) throws InterruptedException, IOException {
        HttpResponse<?> response = httpClient.send(builder.build(), handler);
        return response;
    }

    public CompletableFuture<? extends HttpResponse<?>> sendAsync(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler) throws InterruptedException, IOException {
        CompletableFuture<? extends HttpResponse<?>> response = httpClient.sendAsync(builder.build(), handler);
        return response;
    }

    public HttpRequest.Builder initBuilder(String url,  HttpMethod method) throws Exception{
        return initBuilder(new URI(url), method, Optional.empty());
    }


    public HttpRequest.Builder initBuilder(String url,  HttpMethod method, Optional<?> body) throws Exception{
        return initBuilder(new URI(url), method, body);
    }

    public HttpRequest.Builder initBuilder(URI uri,  HttpMethod method) {
        return initBuilder(uri, method, Optional.empty());
    }

    public HttpRequest.Builder initBuilder(URI uri,  HttpMethod method, Optional<?> body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri);
        if (HttpMethod.DELETE.equals(method)) {
            builder.DELETE();
        } else  if (HttpMethod.POST.equals(method)) {
            builder.POST(getBodyPublisher(body));
        } else  if (HttpMethod.PUT.name().equals(method)) {
            builder.PUT(getBodyPublisher(body));
        }
        //GET is default method
        return builder;
    }

    protected HttpRequest.BodyPublisher getBodyPublisher(Optional<?> body) {
        if (body.isPresent()) {
            if (body.get() instanceof String ) {
                return HttpRequest.BodyPublishers.ofString((String)body.get());
            } else if (body.get() instanceof Map) {
                return ofFormData((Map)body.get());
            } else {
                return HttpRequest.BodyPublishers.ofString(JsonMapper.toJson(body.get()));
            }
        }
        return null;
        //TODO add binary data BodyPublishers
    }

    private  HttpRequest.BodyPublisher ofFormData(Map<Object, Object> data) {
        var builder = new StringBuilder();
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
        }
        return HttpRequest.BodyPublishers.ofString(builder.toString());
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
