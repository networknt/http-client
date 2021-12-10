package com.networknt.http.client;

import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HttpClientRequestTest {

    private static HttpClientRequest httpClientRequest;
    @Test
    public void testGetRequest() throws Exception{
        httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8443/v1/pets", HttpMethod.GET);
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        // print status code
        System.out.println(response.statusCode());

        // print response body
        System.out.println(response.body());
    }

}
