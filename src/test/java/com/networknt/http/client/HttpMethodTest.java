package com.networknt.http.client;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HttpMethodTest {

    @Test
    public void testGet() {
        assertTrue(HttpMethod.GET.name().equals("GET"));
    }

}
