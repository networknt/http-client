package com.networknt.client.oauth;

import tools.jackson.core.JacksonException;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OAuthHelperTest {
    @Test
    void testUpdateJwtWithTokenResponse_Success() throws JacksonException {
        // Arrange
        Jwt jwt = new Jwt();
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzI3MjAwMDB9.signature");
        tokenResponse.setScope("read write");

        // Act
        Result<Jwt> result = OauthHelper.updateJwtWithTokenResponse(jwt, tokenResponse);

        // Assert
        Assertions.assertTrue(result.isSuccess());
        Jwt updatedJwt = result.getResult();
        Assertions.assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzI3MjAwMDB9.signature", updatedJwt.getJwt());
        Assertions.assertEquals(1672720000000L, updatedJwt.getExpire()); // Expected expiration time in milliseconds
        Assertions.assertEquals("read write", updatedJwt.getScopes());
    }

    @Test
    void testUpdateJwtWithTokenResponse_ErrorParsingJwtExp() {
        // Arrange
        Jwt jwt = new Jwt();
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("invalid.jwt.token");

        // Act
        Result<Jwt> result = OauthHelper.updateJwtWithTokenResponse(jwt, tokenResponse);

        // Assert
        Assertions.assertTrue(result.isFailure());
        Status status = result.getError();
        Assertions.assertEquals("ERR10052", status.getCode());
        Assertions.assertEquals("GET_TOKEN_ERROR", status.getMessage());
    }
    private String tokenWithExpiry(String jsonValue) {
        String payload = "{\"exp\":" + jsonValue + "}";
        return "header." + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + ".signature";
    }

    @Test
    void numericStringExpiryIsMeasuredDirectly() {
        Assertions.assertEquals(123_000L, OauthHelper.getJwtExp(tokenWithExpiry("\"123\"")));
    }

    @Test
    void nonNumericExpiryRetainsExistingTokenAndReturnsFailure() {
        Jwt jwt = new Jwt();
        jwt.setJwt("previous-token");
        jwt.setExpire(456_000L);
        jwt.setScopes("read");
        TokenResponse response = new TokenResponse();
        response.setAccessToken(tokenWithExpiry("\"not-a-number\""));
        response.setScope("write");
        Result<Jwt> result = OauthHelper.updateJwtWithTokenResponse(jwt, response);
        Assertions.assertTrue(result.isFailure());
        Assertions.assertEquals("ERR10052", result.getError().getCode());
        Assertions.assertEquals("GET_TOKEN_ERROR", result.getError().getMessage());
        Assertions.assertEquals("previous-token", jwt.getJwt());
        Assertions.assertEquals(456_000L, jwt.getExpire());
        Assertions.assertEquals("read", jwt.getScopes());
    }

}
