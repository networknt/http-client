package com.networknt.http.client;

import com.networknt.client.ClientConfig;
import com.networknt.client.oauth.Jwt;
import com.networknt.client.oauth.TokenManager;
import com.networknt.config.Config;
import com.networknt.config.TlsUtil;
import com.networknt.http.client.ssl.ClientX509ExtendedTrustManager;
import com.networknt.http.client.ssl.CompositeX509TrustManager;
import com.networknt.monad.Failure;
import com.networknt.monad.Result;
import com.networknt.utility.ModuleRegistry;
import org.apache.commons.lang3.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;


public class HttpClientRequest {

    private static final Logger logger = LoggerFactory.getLogger(HttpClientRequest.class);
    private static final ClientConfig clientConfig = ClientConfig.get();
    private static SSLContext sslContext = null;
    HttpClient httpClient;

    public static final String TLS = "tls";
    static final String LOAD_TRUST_STORE = "loadTrustStore";
    static final String LOAD_KEY_STORE = "loadKeyStore";
    static final String LOAD_DEFAULT_TRUST = "loadDefaultTrustStore";
    static final String TRUST_STORE = "trustStore";
    static final String TRUST_STORE_PASS = "trustStorePass";
    static final String DEFAULT_CERT_PASS = "defaultCertPassword";
    static final String KEY_STORE = "keyStore";
    static final String KEY_STORE_PASS = "keyStorePass";
    static final String KEY_PASS = "keyPass";
    static final String TLS_VERSION = "tlsVersion";
    static final String KEY_STORE_PROPERTY = "javax.net.ssl.keyStore";
    static final String KEY_STORE_PASSWORD_PROPERTY = "javax.net.ssl.keyStorePassword";
    static final String TRUST_STORE_PROPERTY = "javax.net.ssl.trustStore";
    static final String TRUST_STORE_PASSWORD_PROPERTY = "javax.net.ssl.trustStorePassword";
    static final String TRUST_STORE_TYPE_PROPERTY = "javax.net.ssl.trustStoreType";
    private final TokenManager tokenManager = TokenManager.getInstance();
    private String proxyHost = null;
    private int proxyPort;
    private Authenticator authenticator = null;
    private ExecutorService executorService = null;

    public HttpClientRequest() {
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
     * @param executorService the Executor
     *
     */
    public void setExecutorService(ExecutorService executorService) {
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
                .connectTimeout(Duration.ofMillis(clientConfig.getTimeout()));
        if (isHttps) {
            try {
                clientBuilder.sslContext(createSSLContext());
            } catch (IOException e) {
                logger.error("cannot initial http client:" + e);
            }
        }
        if (clientConfig.getRequestEnableHttp2()) {
            clientBuilder.version(HttpClient.Version.HTTP_2);
        } else {
            clientBuilder.version(HttpClient.Version.HTTP_1_1);
        }
        if(this.proxyHost != null) clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(this.proxyHost, this.proxyPort == 0 ? 443 : this.proxyPort)));
        if(this.authenticator != null)  clientBuilder.authenticator(this.authenticator);
        if(this.executorService != null)  clientBuilder.executor(this.executorService);
        return clientBuilder.build();
    }

    public HttpResponse<?> send(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler) throws InterruptedException, IOException {
        return sendWithRetry(builder, handler, clientConfig.getMaxRequestRetry());
    }

    public CompletableFuture<? extends HttpResponse<?>> sendAsync(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler) throws InterruptedException, IOException {
        return sendAsyncWithRetry(builder, handler, clientConfig.getMaxRequestRetry());
    }

    private HttpResponse<?> sendWithRetry(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler, int retries) throws InterruptedException, IOException {
        for (int attempt = 1; attempt <= retries; attempt++) {
            try {
                return httpClient.send(builder.build(), handler);
            } catch (IOException | InterruptedException e) {
                if (attempt == retries) {
                    throw e;
                }
                if(clientConfig.getRequestRetryDelay() > 0) {
                    TimeUnit.MILLISECONDS.sleep(clientConfig.getRequestRetryDelay());
                }
            }
        }
        throw new IOException("Failed to send request after " + retries + " attempts");
    }

    private CompletableFuture<? extends HttpResponse<?>> sendAsyncWithRetry(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler, int retries) throws InterruptedException, IOException {
        CompletableFuture<HttpResponse<?>> future = new CompletableFuture<>();
        sendAsyncWithRetry(builder, handler, retries, future, 1);
        return future;
    }

    private void sendAsyncWithRetry(HttpRequest.Builder builder, HttpResponse.BodyHandler<?> handler, int retries, CompletableFuture<HttpResponse<?>> future, int attempt) {
        httpClient.sendAsync(builder.build(), handler).whenComplete((response, throwable) -> {
            if (throwable == null) {
                future.complete(response);
            } else {
                if (attempt < retries) {
                    try {
                        if(clientConfig.getRequestRetryDelay() > 0) {
                            TimeUnit.MILLISECONDS.sleep(clientConfig.getRequestRetryDelay());
                        }
                    } catch (InterruptedException e) {
                        future.completeExceptionally(e);
                        return;
                    }
                    sendAsyncWithRetry(builder, handler, retries, future, attempt + 1);
                } else {
                    future.completeExceptionally(throwable);
                }
            }
        });
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
                .timeout(Duration.ofMillis(clientConfig.getTimeout()))
                .uri(uri);
        if (HttpMethod.DELETE.equals(method)) {
            builder.DELETE();
        } else if (HttpMethod.POST.equals(method)) {
            builder.POST(getBodyPublisher(body));
        } else if (HttpMethod.PUT.equals(method)) {
            builder.PUT(getBodyPublisher(body));
        } else if (HttpMethod.PATCH.equals(method)) {
            builder.method("PATCH", getBodyPublisher(body));
        }
        // GET is the default method.
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
     * @param builder the http request builder
     * @param requestPath the request path
     * @param scopes the scopes
     * @param serviceId the service id
     * @return Result when fail to get jwt, it will return a Status.
     */
    public Result addCcToken(HttpRequest.Builder builder, String requestPath, String scopes, String serviceId) {
        Result<Jwt> result = tokenManager.getJwt(requestPath, scopes, serviceId);
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
     * @param requestPath the request path
     * @param scopes the scopes
     * @param serviceId the service id
     * @return Result when fail to get jwt, it will return a Status.
     */
    public Result populateHeader(HttpRequest.Builder builder, String authToken, String requestPath, String scopes, String serviceId) {
        Result<Jwt> result = tokenManager.getJwt(requestPath, scopes, serviceId);
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
     * create ssl context using specified trustedName config
     *
     * @return SSLContext
     * @throws IOException IOException
     */
    @SuppressWarnings("unchecked")
    public static SSLContext createSSLContext() throws IOException {
        // return the cached sslContext if it is not null.
        if(sslContext != null) return sslContext;
        KeyManager[] keyManagers = null;
        Map<String, Object> tlsMap = clientConfig.getTlsConfig();
        if(tlsMap != null) {
            try {
                // load key store for client certificate if two way ssl is used.
                Boolean loadKeyStore = tlsMap.get(LOAD_KEY_STORE) == null ? false : Config.loadBooleanValue(LOAD_KEY_STORE, tlsMap.get(LOAD_KEY_STORE));
                if (loadKeyStore != null && loadKeyStore) {
                    String keyStoreName = System.getProperty(KEY_STORE_PROPERTY);
                    String keyStorePass = System.getProperty(KEY_STORE_PASSWORD_PROPERTY);
                    if (keyStoreName != null && keyStorePass != null) {
                        if(logger.isInfoEnabled()) logger.info("Loading key store from system property at " + Encode.forJava(keyStoreName));
                    } else {
                        keyStoreName = (String) tlsMap.get(KEY_STORE);
                        keyStorePass = (String) tlsMap.get(KEY_STORE_PASS);
                        if(keyStorePass == null) {
                            logger.error("Cannot load the config: " +  KEY_STORE_PASS + " from client.yml");
                        }
                        if(logger.isInfoEnabled()) logger.info("Loading key store from config at " + Encode.forJava(keyStoreName));
                    }
                    if (keyStoreName != null && keyStorePass != null) {
                        String keyPass = (String) tlsMap.get(KEY_PASS);
                        if(keyPass == null) {
                            logger.error("Cannot load the config: " + KEY_PASS + " from client.yml");
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
            Boolean loadDefaultTrust = tlsMap.get(LOAD_DEFAULT_TRUST) == null ? false : Config.loadBooleanValue(LOAD_DEFAULT_TRUST, tlsMap.get(LOAD_DEFAULT_TRUST));
            List<TrustManager> trustManagerList = new ArrayList<>();
            try {
                // load trust store, this is the server public key certificate
                // first check if javax.net.ssl.trustStore system properties is set. It is only necessary if the server
                // certificate doesn't have the entire chain.
                Boolean loadTrustStore = tlsMap.get(LOAD_TRUST_STORE) == null ? false : Config.loadBooleanValue(LOAD_TRUST_STORE, tlsMap.get(LOAD_TRUST_STORE));
                if (loadTrustStore != null && loadTrustStore) {

                    String trustStoreName = (String) tlsMap.get(TRUST_STORE);;
                    String trustStorePass = (String) tlsMap.get(TRUST_STORE_PASS);
                    if(trustStorePass == null) {
                        logger.error("Cannot load the config: "  + TRUST_STORE_PASS + " from client.yml");
                    }
                    if(logger.isInfoEnabled())
                        logger.info("Loading trust store from config at {}", Encode.forJava(trustStoreName));
                    if (trustStoreName != null && trustStorePass != null) {
                        KeyStore trustStore = TlsUtil.loadKeyStore(trustStoreName, trustStorePass.toCharArray());
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(trustStore);
                        trustManagers = trustManagerFactory.getTrustManagers();
                    }
                    if (loadDefaultTrust != null && loadDefaultTrust) {
                        TrustManager[] defaultTrusts = loadDefaultTrustStore();
                        if (defaultTrusts!=null && defaultTrusts.length>0) {
                            trustManagerList.addAll(Arrays.asList(defaultTrusts));
                        }
                    }
                    if (trustManagers!=null && trustManagers.length>0) {
                        trustManagerList.addAll(Arrays.asList(trustManagers));
                    }
                }
            } catch (Exception e) {
                throw new IOException("Unable to initialise TrustManager[]", e);
            }

            try {
                String tlsVersion = (String)tlsMap.get(TLS_VERSION);
                if(tlsVersion == null) tlsVersion = "TLSv1.3";
                sslContext = SSLContext.getInstance(tlsVersion);
                if (loadDefaultTrust != null && loadDefaultTrust && !trustManagerList.isEmpty()) {
                    TrustManager[] compositeTrustManagers = {new CompositeX509TrustManager(convertTrustManagers(trustManagerList))};
                    sslContext.init(keyManagers, compositeTrustManagers, null);
                } else {
                    if(trustManagers == null || trustManagers.length == 0) {
                        logger.error("No trust store is loaded. Please check client.yml");
                    } else {
                        TrustManager[] extendedTrustManagers = {new ClientX509ExtendedTrustManager(trustManagerList)};
                        sslContext.init(keyManagers, extendedTrustManagers, null);
                    }
                }
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new IOException("Unable to create and initialise the SSLContext", e);
            }
        } else {
            logger.error("TLS configuration section is missing in client.yml");
        }
        // register the client config to the module registry.
        if(logger.isTraceEnabled()) logger.trace("Registering client config to module registry");
        List<String> masks = List.of("client_secret", "trustStorePass", "keyStorePass", "keyPass");
        ModuleRegistry.registerModule(
                ClientConfig.CONFIG_NAME,
                HttpClientRequest.class.getName(),
                Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(ClientConfig.CONFIG_NAME),
                masks
        );

        return sslContext;
    }

    public static List<X509TrustManager> convertTrustManagers(List<TrustManager> trustManagerList) {
        List<X509TrustManager> x509TrustManagers = new ArrayList<>();
        for (TrustManager trustManager : trustManagerList) {
            if (trustManager instanceof X509TrustManager) {
                x509TrustManagers.add((X509TrustManager) trustManager);
            }
        }
        return x509TrustManagers;
    }

    public  static  TrustManager[] loadDefaultTrustStore() throws Exception {
        Path location = null;
        String password = "changeit"; //default value for cacerts, we can override it from config
        Map<String, Object> tlsMap = clientConfig.getTlsConfig();
        if(tlsMap != null &&  tlsMap.get(DEFAULT_CERT_PASS)!=null) {
            password = (String)tlsMap.get(DEFAULT_CERT_PASS);
        }
        String locationProperty = System.getProperty(TRUST_STORE_PROPERTY);
        if (!StringUtils.isEmpty(locationProperty)) {
            Path p = Paths.get(locationProperty);
            File f = p.toFile();
            if (f.exists() && f.isFile() && f.canRead()) {
                location = p;
            }
        }  else {
            String javaHome = System.getProperty("java.home");
            location = Paths.get(javaHome, "lib", "security", "jssecacerts");
            if (!location.toFile().exists()) {
                location = Paths.get(javaHome, "lib", "security", "cacerts");
            }
        }
        if (!location.toFile().exists()) {
            logger.warn("Cannot find system default trust store");
            return null;
        }

        String trustStorePass = System.getProperty(TRUST_STORE_PASSWORD_PROPERTY);
        if (!StringUtils.isEmpty(trustStorePass)) {
            password = trustStorePass;
        }
        String trustStoreType = System.getProperty(TRUST_STORE_TYPE_PROPERTY);
        String type;
        if (!StringUtils.isEmpty(trustStoreType)) {
            type = trustStoreType;
        } else {
            type = KeyStore.getDefaultType();
        }
        KeyStore trustStore = KeyStore.getInstance(type, Security.getProvider("SUN"));
        try (InputStream is = Files.newInputStream(location)) {
            trustStore.load(is, password.toCharArray());
            logger.info("JDK default trust store loaded from : {} .", location );
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();

    }

}
