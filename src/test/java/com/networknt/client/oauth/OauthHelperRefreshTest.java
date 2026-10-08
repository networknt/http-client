package com.networknt.client.oauth;

import com.networknt.monad.Failure;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OauthHelperRefreshTest {
    @Test
    void freshTokenDoesNotWaitForJwtMonitor() throws Exception {
        Jwt jwt = new Jwt();
        jwt.setJwt("cached-token");
        jwt.setExpire(System.currentTimeMillis() + Jwt.getTokenRenewBeforeExpired() + 60000);
        CountDownLatch monitorHeld = new CountDownLatch(1);
        CountDownLatch releaseMonitor = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> holder = executor.submit(() -> {
                synchronized (jwt) {
                    monitorHeld.countDown();
                    try {
                        assertTrue(releaseMonitor.await(10, TimeUnit.SECONDS));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(e);
                    }
                }
            });
            assertTrue(monitorHeld.await(5, TimeUnit.SECONDS));
            Future<Result<Jwt>> read = executor.submit(() -> OauthHelper.populateCCToken(jwt));
            assertSame(jwt, read.get(5, TimeUnit.SECONDS).getResult());
            assertFalse(jwt.isRenewing());
            releaseMonitor.countDown();
            holder.get(5, TimeUnit.SECONDS);
        } finally {
            releaseMonitor.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void failedSyncRefreshResetsFlagAndUsesExpiredRetryDelay() {
        Jwt jwt = new Jwt();
        long retryDelay = Jwt.getExpiredRefreshRetryDelay();
        try (MockedStatic<OauthHelper> helper = mockStatic(OauthHelper.class, CALLS_REAL_METHODS)) {
            Jwt.setExpiredRefreshRetryDelay(60000);
            helper.when(() -> OauthHelper.getTokenResult(any(TokenRequest.class)))
                    .thenReturn(Failure.of(new Status("ERR10052", "Controlled failure")));
            long before = System.currentTimeMillis();
            Result<Jwt> result = OauthHelper.populateCCToken(jwt);
            assertTrue(result.isFailure());
            assertEquals("ERR10052", result.getError().getCode());
            assertFalse(jwt.isRenewing());
            assertTrue(jwt.getExpiredRetryTimeout() >= before + 60000);
            assertEquals(0, jwt.getEarlyRetryTimeout());
            assertTrue(OauthHelper.populateCCToken(jwt).isFailure());
            helper.verify(() -> OauthHelper.getTokenResult(any(TokenRequest.class)), times(1));
        } finally {
            Jwt.setExpiredRefreshRetryDelay(retryDelay);
        }
    }

    @Test
    void unexpectedSyncFailureResetsFlag() {
        Jwt jwt = new Jwt();
        try (MockedStatic<OauthHelper> helper = mockStatic(OauthHelper.class, CALLS_REAL_METHODS)) {
            helper.when(() -> OauthHelper.getTokenResult(any(TokenRequest.class)))
                    .thenThrow(new IllegalStateException("Controlled exception"));
            assertThrows(IllegalStateException.class, () -> OauthHelper.populateCCToken(jwt));
            assertFalse(jwt.isRenewing());
        }
    }

    @Test
    void malformedRefreshDoesNotReplaceCachedToken() {
        Jwt jwt = new Jwt();
        jwt.setJwt("cached-token");
        jwt.setExpire(123456L);
        jwt.setScopes("cached-scope");
        TokenResponse response = new TokenResponse();
        response.setAccessToken("invalid.jwt.token");
        response.setScope("replacement-scope");
        assertTrue(OauthHelper.updateJwtWithTokenResponse(jwt, response).isFailure());
        assertEquals("cached-token", jwt.getJwt());
        assertEquals(123456L, jwt.getExpire());
        assertEquals("cached-scope", jwt.getScopes());
    }
}
