# http-client
An HTTP client based on JDK 11 http-client to invoke APIs with client-side cross-cutting concerns addressed

The purpose of the client module is trying to help the user to handler SSL cert load and JWT token process.

###  Synchronous call 

```text
        HttpClientRequest httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        int responseStatus = response.statusCode();
        String responseBody = response.body();
```

###  Synchronous call by adding jwt token to the header

```text
        HttpClientRequest httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        httpClientRequest.addCcToken(builder);
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        int responseStatus = response.statusCode();
        String responseBody = response.body();
```

###  Asynchronous call with jwt token

```text
        HttpClientRequest httpClientRequest = new HttpClientRequest();
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.GET);
        builder.setHeader("x-traceability-id", "1111111");
        httpClientRequest.addCcToken(builder);
        CompletableFuture<HttpResponse<String>> response = (CompletableFuture<HttpResponse<String>> )httpClientRequest.sendAsync(builder, HttpResponse.BodyHandlers.ofString());
        // print response body
        System.out.println(response.get().body());
```

###  POST method call by adding jwt token to the header

```text
        httpClientRequest = new HttpClientRequest();
        String requestBody = "{\"name\": \"doggie1\"}";
        HttpRequest.Builder builder = httpClientRequest.initBuilder("https://localhost:8445/v1/pets", HttpMethod.POST, Optional.of(requestBody));
        builder.setHeader("x-traceability-id", "1111111");
        builder.setHeader("Content-Type", "application/json");
        httpClientRequest.addCcToken(builder);
        HttpResponse<String> response = (HttpResponse<String>) httpClientRequest.send(builder, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
```