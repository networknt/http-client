package com.networknt.client.oauth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import com.networknt.client.AuthServerConfig;
import com.networknt.cluster.Cluster;
import com.networknt.service.SingletonServiceFactory;
import org.mockito.ArgumentCaptor;
import com.networknt.http.client.HttpClientRequest;
import org.mockito.MockedStatic;
import org.slf4j.MDC;
import javax.net.ssl.SSLContext;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import ch.qos.logback.core.read.ListAppender;
import com.networknt.client.ClientConfig;
import com.networknt.common.ContentType;
import com.networknt.monad.Result;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OauthHelperLoggingTest {
    private final Logger logger = (Logger) LoggerFactory.getLogger(OauthHelper.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Level previousLevel;
    private final Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    private Level previousRootLevel;
    private Map<String, Object> previousCaches;
    private String previousHostnameVerification;
    private Map<String, String> previousMdc;

    @BeforeEach
    void captureTraceLogs() throws Exception {
        previousLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        previousRootLevel = root.getLevel();
        root.setLevel(Level.TRACE);
        appender.list = new CopyOnWriteArrayList<>();
        appender.start();
        root.addAppender(appender);
        previousCaches = new HashMap<>();
        for (String field : List.of("tokenClient", "introspectionClient", "signClient", "derefClient", "clientConfig")) {
            previousCaches.put(field, cache(field));
        }
        previousHostnameVerification = System.getProperty("jdk.internal.httpclient.disableHostnameVerification");
        previousMdc = MDC.getCopyOfContextMap();
    }

    @AfterEach
    void restoreLogging() throws Exception {
        for (Map.Entry<String, Object> entry : previousCaches.entrySet()) cache(entry.getKey(), entry.getValue());
        if (previousHostnameVerification == null) System.clearProperty("jdk.internal.httpclient.disableHostnameVerification");
        else System.setProperty("jdk.internal.httpclient.disableHostnameVerification", previousHostnameVerification);
        MDC.clear();
        if (previousMdc != null) MDC.setContextMap(previousMdc);
        root.detachAppender(appender);
        root.setLevel(previousRootLevel);
        appender.stop();
        logger.setLevel(previousLevel);
    }

    @Test
    void successfulTokenResponseDoesNotLogTokensOrUnknownFields() throws Exception {
        String body = "{\"access_token\":\"access-canary\",\"refresh_token\":\"refresh-canary\","
                + "\"token_type\":\"bearer\",\"expires_in\":3600,\"custom_secret\":\"custom-canary\"}";
        Result<TokenResponse> result = handleResponse(ContentType.APPLICATION_JSON, body);
        assertTrue(result.isSuccess());
        assertEquals("access-canary", result.getResult().getAccessToken());
        assertEquals("refresh-canary", result.getResult().getRefreshToken());
        assertNoCanaries();
        assertFalse(appender.list.isEmpty(), "Non-sensitive diagnostics should remain available");
    }

    @Test
    void jsonErrorResponseDoesNotLogSensitiveDescription() throws Exception {
        String body = "{\"statusCode\":400,\"code\":\"ERR10052\",\"message\":\"GET_TOKEN_ERROR\","
                + "\"description\":\"error-canary\"}";
        Result<TokenResponse> result = handleResponse(ContentType.APPLICATION_JSON, body);
        assertTrue(result.isFailure());
        assertEquals("ERR10052", result.getError().getCode());
        assertEquals("error-canary", result.getError().getDescription());
        assertNoCanaries();
    }

    @Test
    void nonJsonErrorResponseIsReturnedWithoutLoggingItsBody() throws Exception {
        Result<TokenResponse> result = handleResponse(ContentType.ANY_TYPE, "provider-canary");
        assertTrue(result.isFailure());
        assertEquals("ERR10052", result.getError().getCode());
        assertTrue(result.getError().getDescription().contains("provider-canary"));
        assertNoCanaries();
    }

    @Test
    void emptyResponseRetainsFailureBehavior() throws Exception {
        assertTrue(handleResponse(ContentType.APPLICATION_JSON, "").isFailure());
        assertTrue(handleResponse(ContentType.APPLICATION_JSON, null).isFailure());
        assertNoCanaries();
    }

    @Test
    void refreshFormRetainsCredentialsWithoutLoggingThem() throws Exception {
        RefreshTokenRequest request = mock(RefreshTokenRequest.class);
        when(request.getGrantType()).thenReturn(ClientConfig.REFRESH_TOKEN);
        when(request.getRefreshToken()).thenReturn("refresh-canary");
        when(request.getCsrf()).thenReturn("csrf-canary");
        String form = URLDecoder.decode(OauthHelper.getEncodedString(request), StandardCharsets.UTF_8);
        assertTrue(form.contains("refresh_token=refresh-canary"));
        assertTrue(form.contains("csrf=csrf-canary"));
        assertNoCanaries();
    }

    @Test
    void authorizationCodeFormRetainsCodeWithoutLoggingIt() throws Exception {
        AuthorizationCodeRequest request = mock(AuthorizationCodeRequest.class);
        when(request.getGrantType()).thenReturn(ClientConfig.AUTHORIZATION_CODE);
        when(request.getAuthCode()).thenReturn("code-canary");
        when(request.getCsrf()).thenReturn("csrf-canary");
        String form = URLDecoder.decode(OauthHelper.getEncodedString(request), StandardCharsets.UTF_8);
        assertTrue(form.contains("code=code-canary"));
        assertTrue(form.contains("csrf=csrf-canary"));
        assertNoCanaries();
    }

    @Test
    @SuppressWarnings("unchecked")
    void publicTokenRequestDoesNotLogClientSecrets() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.body()).thenReturn("{\"access_token\":\"access-canary\"}");
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        Field clientField = OauthHelper.class.getDeclaredField("tokenClient");
        Field configField = OauthHelper.class.getDeclaredField("clientConfig");
        clientField.setAccessible(true);
        configField.setAccessible(true);
        Object previousClient = clientField.get(null);
        Object previousConfig = configField.get(null);
        try {
            clientField.set(null, client);
            configField.set(null, ClientConfig.get());
            TokenRequest request = new TokenRequest();
            request.setServerUrl("https://example.invalid");
            request.setUri("/token");
            request.setGrantType("client_credentials");
            request.setClientId("test-client");
            request.setClientSecret("secret-canary");
            Result<TokenResponse> result = OauthHelper.getTokenResult(request);
            assertTrue(result.isSuccess());
            assertEquals("access-canary", result.getResult().getAccessToken());
            assertNoCanaries();
        } finally {
            clientField.set(null, previousClient);
            configField.set(null, previousConfig);
        }
    }

    @Test
    void jsonNullIsAControlledFailure() throws Exception {
        Result<TokenResponse> result = handleResponse(ContentType.APPLICATION_JSON, "null");
        assertTrue(result.isFailure());
        assertEquals("ERR10052", result.getError().getCode());
    }

    @Test
    void malformedProviderJsonDoesNotLeakThroughExceptions() throws Exception {
        HttpClient client = httpResponse("{\"access_token\": token-canary}", "application/json", 200);
        cache("tokenClient", client);
        assertTrue(OauthHelper.getTokenResult(tokenRequest()).isFailure());
        assertNoCanaries();
    }

    @Test
    void clientCredentialsSuccessDoesNotLogRequestSecret() throws Exception {
        long expiry = System.currentTimeMillis() / 1000 + 3600;
        String jwtToken = "header." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"exp\":" + expiry + "}").getBytes(StandardCharsets.UTF_8)) + ".signature";
        cache("tokenClient", httpResponse("{\"access_token\":\"" + jwtToken + "\"}", "application/json", 200));
        Jwt jwt = credentialsJwt();
        assertTrue(OauthHelper.populateCCToken(jwt).isSuccess());
        assertEquals(jwtToken, jwt.getJwt());
        assertNoCanaries();
    }

    @Test
    void syncRefreshDoesNotLogNonJsonProviderErrorStatus() throws Exception {
        cache("tokenClient", httpResponse("provider-canary", "text/plain", 400));
        Result<Jwt> result = OauthHelper.populateCCToken(credentialsJwt());
        assertTrue(result.isFailure());
        assertTrue(result.getError().getDescription().contains("provider-canary"));
        assertNoCanaries();
    }

    @Test
    void asyncRefreshDoesNotLogJsonErrorStatus() throws Exception {
        cache("tokenClient", httpResponse("{\"statusCode\":400,\"code\":\"provider-canary\","
                + "\"message\":\"message-canary\",\"description\":\"description-canary\"}", "application/json", 400));
        Jwt jwt = credentialsJwt();
        jwt.setJwt("cached-token");
        jwt.setExpire(System.currentTimeMillis() + 30_000);
        long previousRenewBefore = Jwt.getTokenRenewBeforeExpired();
        try {
            Jwt.setTokenRenewBeforeExpired(60_000);
            assertTrue(OauthHelper.populateCCToken(jwt).isSuccess());
            awaitRefresh(jwt);
            assertEquals("cached-token", jwt.getJwt());
            assertNoCanaries();
        } finally {
            awaitRefresh(jwt);
            Jwt.setTokenRenewBeforeExpired(previousRenewBefore);
        }
    }

    @Test
    void asyncRefreshDoesNotLogExceptionMessagesOrCauses() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IllegalStateException("exception-canary", new RuntimeException("cause-canary")));
        cache("tokenClient", client);
        Jwt jwt = credentialsJwt();
        jwt.setExpire(System.currentTimeMillis() + 30_000);
        long previousRenewBefore = Jwt.getTokenRenewBeforeExpired();
        try {
            Jwt.setTokenRenewBeforeExpired(60_000);
            assertTrue(OauthHelper.populateCCToken(jwt).isSuccess());
            awaitRefresh(jwt);
            assertNoCanaries();
        } finally {
            awaitRefresh(jwt);
            Jwt.setTokenRenewBeforeExpired(previousRenewBefore);
        }
    }

    @Test
    void malformedJwtPayloadDoesNotLeakThroughParseException() {
        TokenResponse response = new TokenResponse();
        response.setAccessToken("header." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"exp\":token-canary}".getBytes(StandardCharsets.UTF_8)) + ".signature");
        assertTrue(OauthHelper.updateJwtWithTokenResponse(new Jwt(), response).isFailure());
        assertNoCanaries();
    }

    @Test
    void introspectionDoesNotLogRequestOrResponseSecrets() throws Exception {
        cache("introspectionClient", httpResponse("{\"sub\":\"identity-canary\"}", "application/json", 200));
        IntrospectionRequest request = new IntrospectionRequest("token-canary");
        request.setServerUrl("https://example.invalid");
        request.setUri("/introspect");
        request.setClientId("client");
        request.setClientSecret("secret-canary");
        Result<String> result = OauthHelper.getIntrospection("token-canary", request);
        assertTrue(result.isSuccess());
        assertTrue(result.getResult().contains("identity-canary"));
        assertNoCanaries();
    }

    @Test
    void keyEndpointErrorDoesNotLogRequestSecretOrProviderBody() throws Exception {
        HttpClient client = httpResponse("key-response-canary", "text/plain", 400);
        HttpClient.Builder builder = mock(HttpClient.Builder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);
        try (MockedStatic<HttpClient> http = mockStatic(HttpClient.class);
             MockedStatic<HttpClientRequest> tls = mockStatic(HttpClientRequest.class)) {
            http.when(HttpClient::newBuilder).thenReturn(builder);
            tls.when(HttpClientRequest::createSSLContext).thenReturn(SSLContext.getDefault());
            KeyRequest request = new KeyRequest("key-id");
            request.setServerUrl("https://example.invalid");
            request.setUri("/key");
            request.setClientId("client");
            request.setClientSecret("secret-canary");
            assertEquals("key-response-canary", OauthHelper.getKey(request));
            assertNoCanaries();
        }
    }

    @Test
    void captureDetectsOtherLoggersArgumentsMdcAndThrowableChains() {
        Logger other = (Logger) LoggerFactory.getLogger("oauth-canary-capture-test");
        Level previous = other.getLevel();
        try {
            other.setLevel(Level.TRACE);
            other.error("Unformatted argument", new Object[] {"argument-canary"});
            assertThrows(AssertionError.class, this::assertNoCanaries);
            appender.list.clear();
            MDC.put("field", "mdc-canary");
            other.info("Safe message");
            assertThrows(AssertionError.class, this::assertNoCanaries);
            appender.list.clear();
            MDC.clear();
            RuntimeException error = new RuntimeException("safe", new RuntimeException("cause-canary"));
            error.addSuppressed(new RuntimeException("suppressed-canary"));
            other.error("Safe message", error);
            assertThrows(AssertionError.class, this::assertNoCanaries);
        } finally {
            other.setLevel(previous);
        }
    }

    @Test
    void discoveredTokenServiceIsUsedWithoutLoggingStaleUrl() throws Exception {
        HttpClient client = httpResponse("{\"access_token\":\"access-canary\"}", "application/json", 200);
        cache("tokenClient", client);
        TokenRequest request = tokenRequest();
        request.setServerUrl(null);
        request.setServiceId("oauth");
        Cluster cluster = mock(Cluster.class);
        when(cluster.serviceToUrl("https", "oauth", null, null)).thenReturn("https://discovered.invalid");
        try (MockedStatic<SingletonServiceFactory> services = mockStatic(SingletonServiceFactory.class)) {
            services.when(() -> SingletonServiceFactory.getBean(Cluster.class)).thenReturn(cluster);
            assertTrue(OauthHelper.getTokenResult(request).isSuccess());
        }
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(client).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("https://discovered.invalid/token", sent.getValue().uri().toString());
        assertNoCanaries();
        assertTrue(appender.list.stream().noneMatch(event -> event.getFormattedMessage().contains("url = null")));
    }

    @Test
    void asyncConstructionFailureDoesNotLogExceptionChain() throws Exception {
        Jwt jwt = credentialsJwt();
        when(jwt.getAuthServerConfig().getClientSecret()).thenThrow(
                new IllegalStateException("exception-canary", new RuntimeException("cause-canary")));
        jwt.setExpire(System.currentTimeMillis() + 30_000);
        long previousRenewBefore = Jwt.getTokenRenewBeforeExpired();
        try {
            Jwt.setTokenRenewBeforeExpired(60_000);
            assertTrue(OauthHelper.populateCCToken(jwt).isSuccess());
            awaitRefresh(jwt);
            assertTrue(appender.list.stream().anyMatch(event -> event.getFormattedMessage().contains("Async token refresh failed")));
            assertNoCanaries();
        } finally {
            awaitRefresh(jwt);
            Jwt.setTokenRenewBeforeExpired(previousRenewBefore);
        }
    }

    @Test
    void introspectionFailureDoesNotLogExceptionMessages() throws Exception {
        HttpClient client = httpResponse("unused", "application/json", 200);
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IllegalStateException("exception-canary", new RuntimeException("cause-canary")));
        cache("introspectionClient", client);
        IntrospectionRequest request = new IntrospectionRequest("token-canary");
        request.setServerUrl("https://example.invalid");
        request.setUri("/introspect");
        assertThrows(com.networknt.exception.ClientException.class,
                () -> OauthHelper.getIntrospection("token-canary", request));
        assertNoCanaries();
    }

    @Test
    void otherTokenResponseCallersDoNotLogMalformedResponseExceptions() throws Exception {
        HttpClient client = httpResponse("{\"access_token\": token-canary}", "application/json", 200);
        cache("tokenClient", client);
        cache("signClient", client);
        SignRequest sign = mock(SignRequest.class);
        when(sign.getServerUrl()).thenReturn("https://example.invalid");
        when(sign.getUri()).thenReturn("/sign");
        assertTrue(OauthHelper.getSignResult(sign, null).isFailure());
        SAMLBearerRequest saml = mock(SAMLBearerRequest.class);
        when(saml.getServerUrl()).thenReturn("https://example.invalid");
        when(saml.getUri()).thenReturn("/token");
        when(saml.getSamlAssertion()).thenReturn("assertion-canary");
        when(saml.getJwtClientAssertion()).thenReturn("client-assertion-canary");
        assertTrue(OauthHelper.getTokenFromSamlResult(saml, null).isFailure());
        TokenExchangeRequest exchange = mock(TokenExchangeRequest.class);
        when(exchange.getServerUrl()).thenReturn("https://example.invalid");
        when(exchange.getUri()).thenReturn("/token");
        when(exchange.getClientId()).thenReturn("client");
        when(exchange.getClientSecret()).thenReturn("secret-canary");
        when(exchange.getSubjectToken()).thenReturn("subject-canary");
        when(exchange.getSubjectTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
        when(exchange.getGrantType()).thenReturn("urn:ietf:params:oauth:grant-type:token-exchange");
        assertTrue(OauthHelper.getTokenFromTokenExchangeResult(exchange, null).isFailure());
        assertNoCanaries();
    }

    private static void assertSafe(String text) {
        assertFalse(text.contains("canary"), "Sensitive canary value reached a log event");
    }

    private static void awaitRefresh(Jwt jwt) throws Exception {
        synchronized (jwt) {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (jwt.isRenewing() && System.nanoTime() < deadline) jwt.wait(100);
            assertFalse(jwt.isRenewing(), "Asynchronous refresh did not finish");
        }
    }

    private Jwt credentialsJwt() {
        AuthServerConfig config = mock(AuthServerConfig.class);
        when(config.getServerUrl()).thenReturn("https://example.invalid");
        when(config.getUri()).thenReturn("/token");
        when(config.getClientId()).thenReturn("client".toCharArray());
        when(config.getClientSecret()).thenReturn("secret-canary".toCharArray());
        Jwt jwt = new Jwt();
        jwt.setAuthServerConfig(config);
        return jwt;
    }

    private TokenRequest tokenRequest() {
        TokenRequest request = new TokenRequest();
        request.setServerUrl("https://example.invalid");
        request.setUri("/token");
        request.setGrantType("client_credentials");
        request.setClientId("client");
        request.setClientSecret("secret-canary");
        return request;
    }

    @SuppressWarnings("unchecked")
    private HttpClient httpResponse(String body, String type, int status) throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.body()).thenReturn(body);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of(type)), (name, value) -> true));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        cache("clientConfig", ClientConfig.get());
        return client;
    }

    private static Object cache(String name) throws Exception {
        Field field = OauthHelper.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private static void cache(String name, Object value) throws Exception {
        Field field = OauthHelper.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }

    private void assertNoCanaries() {
        for (ILoggingEvent event : appender.list) {
            assertSafe(event.getFormattedMessage());
            assertSafe(java.util.Arrays.deepToString(event.getArgumentArray()));
            assertSafe(String.valueOf(event.getMDCPropertyMap()));
            assertSafe(String.valueOf(event.getKeyValuePairs()));
            if (event.getThrowableProxy() != null) assertSafe(ThrowableProxyUtil.asString(event.getThrowableProxy()));
        }
    }

    @SuppressWarnings("unchecked")
    private Result<TokenResponse> handleResponse(ContentType type, String body) throws Exception {
        Method method = OauthHelper.class.getDeclaredMethod("handleResponse", ContentType.class, String.class);
        method.setAccessible(true);
        return (Result<TokenResponse>) method.invoke(null, type, body);
    }
}
