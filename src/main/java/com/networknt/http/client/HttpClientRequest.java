package com.networknt.http.client;

import com.networknt.http.client.monad.Failure;
import com.networknt.http.client.monad.Result;
import com.networknt.http.client.oauth.Jwt;
import com.networknt.http.client.oauth.TokenManager;
import com.networknt.http.client.ssl.TLSConfig;
import com.networknt.http.client.ssl.TlsUtil;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
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
import java.util.concurrent.ExecutorService;

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
    private TokenManager tokenManager = TokenManager.getInstance();
    private String proxyHost = null;
    private int proxyPort;
    private Authenticator authenticator = null;
    private ExecutorService executorService = null;

    public HttpClientRequest() {
        clientConfig = ClientConfig.get();
    }

    /**
     * Selects the proxy server to use, if any, when connecting to the network resource referenced by a URL
     *
     * @param hostname Http call proxy host name.
     * @param port Http call proxy host port number.
     */
    public  void setProxy(String hostname, int port) {
        this.proxyHost = hostname;
        this.proxyPort = port;
    }

    /**
     * Sets the executor to be used for asynchronous and dependent tasks.
     *
     *
     * @param executorService the Executor
     * @return this builder
     */
    public  void setExecutorService(ExecutorService executorService) {
        this.executorService = executorService;
    }

    /**
     * Sets an authenticator to use for HTTP authentication.
     *
     * @param authenticator Http call proxy host name.
     */
    public  void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    protected HttpClient buildHttpClient(ClientConfig clientConfig, boolean isHttps) {

        HttpClient.Builder clientBuilder =  HttpClient.newBuilder()
                .version(clientConfig.getHttpVersion())
                .connectTimeout(Duration.ofMillis(clientConfig.getTimeout()));
        if (isHttps) {
            try {
                clientBuilder.sslContext(createSSLContext());
            } catch (IOException e) {
                logger.error("cannot initial http client:" + e);
            }
        }

        if(this.proxyHost != null) clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(this.proxyHost, this.proxyPort == 0 ? 443 : this.proxyPort)));
        if(this.authenticator != null)  clientBuilder.authenticator(this.authenticator);
        if(this.executorService != null)  clientBuilder.executor(this.executorService);
        return clientBuilder.build();
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

        httpClient = buildHttpClient(clientConfig, "https".equals(uri.getScheme()));
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

    /**
     * Add Authorization Code grant token the caller app gets from OAuth2 server.
     *
     * This is the method called from client like web server
     *
     * @param builder the http request builder
     * @param token the bearer token
     */
    public void addAuthToken(HttpRequest.Builder builder,  String token) {
        if(token != null && !token.startsWith("Bearer ")) {
            if(token.toUpperCase().startsWith("BEARER ")) {
                // other cases of Bearer
                token = "Bearer " + token.substring(7);
            } else {
                token = "Bearer " + token;
            }
        }
        builder.setHeader(Headers.AUTHORIZATION_STRING, token);
    }

    public void addRequestHeader(HttpRequest.Builder builder,  String headerName, String headerValue) {
        builder.setHeader(headerName, headerValue);
    }

    public void addRequestHeaders(HttpRequest.Builder builder,  Map<String, String> headers) {
        if (headers!=null) {
            headers.forEach((k,v)->builder.setHeader(k, v));
        }
    }

    public void addTraceabilityId(HttpRequest.Builder builder,  String traceabilityId) {
        builder.setHeader(Headers.TRACEABILITY_ID_STRING, traceabilityId);
    }

    public void addCorrelationId(HttpRequest.Builder builder,  String correlationId) {
        builder.setHeader(Headers.CORRELATION_ID_STRING, correlationId);
    }

    /**
     * Add Client Credentials token cached in the client for standalone application
     *
     *
     * @param builder the http request builder
     * @return Result when fail to get jwt, it will return a Status.
     */
    public Result addCcToken(HttpRequest.Builder builder) {
        Result<Jwt> result = tokenManager.getJwt();
        if(result.isFailure()) { return Failure.of(result.getError()); }
        builder.setHeader(Headers.AUTHORIZATION_STRING,  "Bearer " + result.getResult().getJwt());
        return result;
    }

    /**
     * Support API to API calls with scope token. The token is the original token from consumer and
     * the client credentials token of caller API is added from cache.
     *
     * This method is used in API to API call
     *
     * @param builder the http request builder
     * @param authToken the authorization token
     * @return Result when fail to get jwt, it will return a Status.
     */
    public Result populateHeader(HttpRequest.Builder builder, String authToken) {
        Result<Jwt> result = tokenManager.getJwt();
        if(result.isFailure()) { return Failure.of(result.getError()); }
        if(authToken == null) {
            authToken = "Bearer " + result.getResult().getJwt();
        } else {
            builder.setHeader(Headers.SCOPE_TOKEN_STRING,  "Bearer " + result.getResult().getJwt());
        }
        addAuthToken(builder, authToken);
        return result;
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
