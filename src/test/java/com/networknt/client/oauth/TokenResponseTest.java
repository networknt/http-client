package com.networknt.client.oauth;

import ch.qos.logback.core.subst.Token;
import com.networknt.config.Config;
import com.networknt.http.client.JsonMapper;
import org.junit.jupiter.api.Test;

public class TokenResponseTest {
    @Test
    public void testTokenResponseWithExtraProperties() {
        String json = "{\"access_token\":\"access_token\",\"token_type\":\"token_type\",\"scope\":\"scope\",\"signature\":\"signature\",\"id\":\"id\", \"issued_at\":1000}";
        try {
            TokenResponse tokenResponse = Config.getInstance().getMapper().readValue(json, TokenResponse.class);
            assert(tokenResponse.getAccessToken().equals("access_token"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testTokenResponseWithExtraPropertiesJsonMapper() {
        String json = "{\"access_token\":\"access_token\",\"token_type\":\"token_type\",\"scope\":\"scope\",\"signature\":\"signature\",\"id\":\"id\", \"issued_at\":1000}";
        TokenResponse tokenResponse = JsonMapper.fromJson(json, TokenResponse.class);
        assert(tokenResponse.getAccessToken().equals("access_token"));
    }

}
