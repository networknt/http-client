package com.networknt.http.client.monad;

import com.fasterxml.jackson.core.JsonProcessingException;

public class Status {
    private int statusCode;
    private String code;
    private String severity;
    private String message;
    private String description;
    public static final String defaultSeverity = "ERROR";

    /**
     * Construct a status object based on all the properties in the object. It is not
     * very often to use this construct to create object.
     *
     * @param statusCode  Status Code
     * @param code        Code
     * @param message     Message
     * @param description Description
     */
    public Status(int statusCode, String code, String message, String description) {
        this.statusCode = statusCode;
        this.code = code;
        this.severity = defaultSeverity;
        this.message = message;
        this.description = description;
    }

    public Status() {
    }

    public Status(String code, String message) {
        this.code = code;
        this.severity = defaultSeverity;
        this.message = message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}
