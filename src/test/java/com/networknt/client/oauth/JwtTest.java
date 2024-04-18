package com.networknt.client.oauth;

import com.networknt.http.client.JsonMapper;

/**
 * Test the Jwt object that can be serialized and deserialized to or from a JSON string.
 */
public class JwtTest {
    public static void main(String[] args) {
        Jwt jwt = new Jwt();
        jwt.setJwt("jwt");
        jwt.setExpire(1000);
        jwt.setRenewing(true);
        jwt.setExpiredRetryTimeout(1000);
        jwt.setEarlyRetryTimeout(1000);
        jwt.setTokenRenewBeforeExpired(1000);
        jwt.setExpiredRefreshRetryDelay(1000);
        jwt.setEarlyRefreshRetryDelay(1000);
        jwt.setScopes("scope1 scope2");

        System.out.println(jwt.getJwt());
        System.out.println(jwt.getExpire());
        System.out.println(jwt.isRenewing());
        System.out.println(jwt.getExpiredRetryTimeout());
        System.out.println(jwt.getEarlyRetryTimeout());
        System.out.println(jwt.getTokenRenewBeforeExpired());
        System.out.println(jwt.getExpiredRefreshRetryDelay());
        System.out.println(jwt.getEarlyRefreshRetryDelay());
        System.out.println(jwt.getScopes());
        String jsonString = JsonMapper.toJson(jwt);
        System.out.println(jsonString);
        jwt = JsonMapper.fromJson(jsonString, Jwt.class);
        System.out.println(jwt.getJwt());
        System.out.println(jwt.getExpire());
        System.out.println(jwt.isRenewing());
        System.out.println(jwt.getExpiredRetryTimeout());
        System.out.println(jwt.getEarlyRetryTimeout());
        System.out.println(jwt.getTokenRenewBeforeExpired());
        System.out.println(jwt.getExpiredRefreshRetryDelay());
        System.out.println(jwt.getEarlyRefreshRetryDelay());
        System.out.println(jwt.getScopes());
    }
}
