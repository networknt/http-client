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

### Connectionpool

JDK 11 http connection build connection pool internal and it will select the connection from pool base on certain logic. 


### Connection with proxy.

If the connection need bridge with proxy, then we need set the proxy for httpClient first:

```text
        httpClientRequest = new HttpClientRequest();
        httpClientRequest.setProxy("https://internal.proxy.com", "443")
```
The token access request will handler proxy based on the proxy setting on the client.yml file:

```text
oauth:
  # OAuth 2.0 token endpoint configuration
  token:
    # token service unique id for OAuth 2.0 provider. If server_url is not set above,
    # a service discovery action will be taken to find an instance of token service.
    serviceId: com.networknt.oauth2-token-1.0.0
    # set to true if the oauth2 provider supports HTTP/2
    # For users who leverage SaaS OAuth 2.0 provider from lightapi.net or others in the public cloud
    # and has an internal proxy server to access code, token and key services of OAuth 2.0, set up the
    # proxyHost here for the HTTPS traffic. This option is only working with server_url and serviceId
    # below should be commented out. OAuth 2.0 services cannot be discovered if a proxy server is used.
    proxyHost:
    # We only support HTTPS traffic for the proxy and the default port is 443. If your proxy server has
    # a different port, please specify it here. If proxyHost is available and proxyPort is missing, then
    # the default value 443 is going to be used for the HTTP connection.
    proxyPort:
```

If the proxyHost set value in the client.yml, the token access will send request call with proxy.

### Connection with HTTP authentication.

If request call need HTTP authentication, sets an authenticator to use for HTTP authentication.

For example:

```text
            Authenticator  authenticator = new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                            "user",
                            "password".toCharArray());
                }
        httpClientRequest = new HttpClientRequest();
        httpClientRequest.setAuthenticator(authenticator);
```

