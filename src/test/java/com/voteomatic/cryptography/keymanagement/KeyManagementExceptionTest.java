package com.voteomatic.cryptography.keymanagement;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyManagementExceptionTest {

    @Test
    void testConstructorWithMessage() {
        String message = "Test key management error";
        KeyManagementException exception = new KeyManagementException(message);
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testConstructorWithMessageAndCause() {
        String message = "Test key management error with cause";
        Throwable cause = new RuntimeException("Root cause");
        KeyManagementException exception = new KeyManagementException(message, cause);
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }
}