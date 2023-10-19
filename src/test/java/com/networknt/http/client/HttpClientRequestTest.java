package com.networknt.http.client;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@Disabled
public class HttpClientRequestTest {

    private static HttpClientRequest httpClientRequest;
    @Test
    public void testGetRequest() throws Exception{
        httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        httpClientRequest.addCcToken(builder, "/v1/pets", null, null);
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        // print status code
        System.out.println(response.statusCode());

        // print response body
        System.out.println(response.body());
    }

    @Test
    public void testPostRequest() throws Exception{
        httpClientRequest = new HttpClientRequest();
        String requestBody = "{\"name\": \"doggie1\"}";
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.POST, Optional.of(requestBody));
        builder.setHeader("x-traceability-id", "1111111");
        builder.setHeader("Content-Type", "application/json");
        httpClientRequest.addCcToken(builder, "/v1/pets", null, null);
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }

    @Test
    public void testGetRequestAsync() throws Exception{
        httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        httpClientRequest.addCcToken(builder, "/v1/pets", null, null);
        CompletableFuture<HttpResponse<String>> response = (CompletableFuture<HttpResponse<String>> )httpClientRequest.sendAsync(builder, HttpResponse.BodyHandlers.ofString());
        // print response body
        System.out.println(response.get().body());
    }
}
