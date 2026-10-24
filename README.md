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

### TLS context load info

Java HttpClient by default will load default JDK cacerts for https request, if the API call doesn't include self-signed cert, we can leave the :

```
  # trust store contains certifictes that server needs. Enable if tls is used.
  loadTrustStore: false
```

If we need load self-signed trust from client truststore, set the config value to true:

```
  # trust store contains certifictes that server needs. Enable if tls is used.
  loadTrustStore: true
```

System will load the client truststore and default certs together for SSL context


### Jackson 3 migration

The development line uses Jackson 3.2.3 (`tools.jackson.core` coordinates and
`tools.jackson` Java packages). Annotation packages remain under
`com.fasterxml.jackson.annotation`. Public mapper/Jackson exception APIs are
source and binary incompatible. Coordinate light-4j and downstream consumers
and decide the next-major release before publishing; project versions remain
unchanged during implementation. The pre-migration `2.x` branch preserves the
Jackson 2 API.

`com.networknt.http.client.JsonMapper.objectMapper` is built immutably with the
measured common Jackson 2 feature profile. It retains plain BigDecimals,
omission of null properties and null map contents, permissive unknown-property
handling, empty-bean serialization, property order, primitive-null coercion,
trailing-token handling and getter-backed collection binding. Unlike the
light-4j config helper, this mapper retains timestamp date/time output: Instant
uses numeric timestamps and LocalDate uses an array. Java-time support is built
in; the separate module is removed. Common-feature snapshots do not establish
parity for removed/renamed flags or arbitrary application types.

Jackson 3 failures are unchecked `JacksonException` instances. The JSON helpers
retain RuntimeException wrapping. OAuth token parsing retains its failure result
and escape fallback, while network IOException catches remain in place. A
malformed JSON document now reports StreamReadException rather than the former
JsonParseException.

Build order: install migrated light-4j lower modules in the same isolated Maven
repository before building this repository; install http-client there before
building the rest of light-4j. These local installs do not publish snapshots to
remote repositories. Classic SnakeYAML pins remain for the final cleanup phase.


Accepted Optional difference: this mapper previously registered only Java-time
support and rejected `Optional.of("x")` with InvalidDefinitionException.
Jackson 3 includes Optional support and writes that value as `"x"`. This built-in
behavior was explicitly accepted during migration and has regression coverage.


The HTTP mapper now derives its common policy from the public
`com.networknt.config.Jackson2Defaults.builder()` in migrated light-4j. It keeps
its own unknown-property, empty-bean, null inclusion and plain-decimal overrides.
Read/write depth remains 1,000 and string length remains 20,000,000, matching
Jackson 2.22.3; the other measured stream limits are shared as well. Common
feature snapshots are owned by light-4j config tests; HTTP tests verify its
overrides and nested input rather than copying that reflective test fixture.

JWT `exp` numeric strings remain accepted (`"123"` means 123,000 milliseconds).
A non-numeric `exp` returns `GET_TOKEN_ERROR` and preserves the existing token,
expiry and scopes. Both paths have direct regression tests.

Build this PR together with light-4j #2814. Its
`scripts/verify-jackson3-bootstrap.sh` builds the coupled sources using a
dedicated Maven repository containing no cached networknt artifacts. Existing
snapshot coordinates do not distinguish Jackson 2 from Jackson 3 artifacts;
coordinated next-major publication and separate-cache resolution remain release
gates.
