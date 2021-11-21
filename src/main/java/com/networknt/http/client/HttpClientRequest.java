package com.networknt.http.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.time.Duration;

public class HttpClientRequest {

    private  Logger logger = LoggerFactory.getLogger(HttpClientRequest.class);
    final String CLIENT_YML_CONFIG = "client.yml";
    final String CLIENT_YAML_CONFIG = "client.yaml";
    private ClientConfig clientConfig;
    HttpClient httpClient;

    public HttpClientRequest() {
        try {
            InputStream in = this.getClass().getClassLoader().getResourceAsStream(CLIENT_YAML_CONFIG);
            if (in == null) {
                in = this.getClass().getClassLoader().getResourceAsStream(CLIENT_YML_CONFIG);
                if (in==null) {
                    throw new IOException("cannot load openapi spec file");
                }
            }
            clientConfig = ClientConfig.get(in);
        } catch (Exception e) {
            logger.error("initial failed:" + e);
        }
        httpClient = buildHttpClient(clientConfig);
    }

    public HttpClientRequest(String configPath) {
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(configPath);
        clientConfig = ClientConfig.get(in);
    }

    public HttpClientRequest(InputStream in) {
        clientConfig = ClientConfig.get(in);
    }

    protected HttpClient buildHttpClient(ClientConfig clientConfig) {
        return HttpClient.newBuilder()
                .version(clientConfig.getHttpVersion())
                .connectTimeout(Duration.ofMillis(clientConfig.getTimeout()))
                .build();

    }

}
