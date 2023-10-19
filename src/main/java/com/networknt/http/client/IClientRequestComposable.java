package com.networknt.http.client;


import com.networknt.client.oauth.TokenRequest;
import java.net.http.HttpRequest;

/**
 * An interface to describe that a HttpRequest can be composed by a TokenRequest. TokenRequest info should be the
 * same for different OAuth servers, but different OAuth servers may have different way to accept request.
 *
 * @author Steve Hu
 */
public interface IClientRequestComposable {
    /**
     * compose an actual HttpRequest based on the given TokenRequest model.
     * @param tokenRequest token request
     * @return HttpRequest
     */
    HttpRequest composeClientRequest(TokenRequest tokenRequest);

}
