package com.networknt.http.client;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@Disabled
public class HttpRequestSSLTest {

    private static HttpClientRequest httpClientRequest;
    @Test
    public void testGetRequest() throws Exception{
        httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://www.google.com", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        // print status code
        System.out.println(response.statusCode());

        // print response body
        System.out.println(response.body());
    }


}
