package com.networknt.client.oauth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
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

    @BeforeEach
    void captureTraceLogs() {
        previousLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void restoreLogging() {
        logger.detachAppender(appender);
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

    private void assertNoCanaries() {
        for (ILoggingEvent event : appender.list) {
            assertFalse(event.getFormattedMessage().contains("-canary"),
                    "Sensitive canary value reached an OAuth log event");
        }
    }

    @SuppressWarnings("unchecked")
    private Result<TokenResponse> handleResponse(ContentType type, String body) throws Exception {
        Method method = OauthHelper.class.getDeclaredMethod("handleResponse", ContentType.class, String.class);
        method.setAccessible(true);
        return (Result<TokenResponse>) method.invoke(null, type, body);
    }
}
