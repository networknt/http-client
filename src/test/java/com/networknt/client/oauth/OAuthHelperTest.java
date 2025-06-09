package com.networknt.client.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OAuthHelperTest {
    @Test
    void testUpdateJwtWithTokenResponse_Success() throws JsonProcessingException {
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
}
