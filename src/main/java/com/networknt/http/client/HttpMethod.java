package com.networknt.http.client;

public enum HttpMethod {

    GET("GET"),
    POST("POST"),
    PUT("PUT"),
    DELETE("DELETE");

    public final String methodString;

    HttpMethod(String methodString) {
        this.methodString = methodString;
    }
}
