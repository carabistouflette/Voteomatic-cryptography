package com.voteomatic.cryptography.core.zkp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ZkpExceptionTest {

    @Test
    void constructorWithMessage() {
        String errorMessage = "Test ZKP error message";
        ZkpException exception = new ZkpException(errorMessage);

        assertEquals(errorMessage, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void constructorWithMessageAndCause() {
        String errorMessage = "Test ZKP error message with cause";
        Throwable cause = new RuntimeException("Root cause");
        ZkpException exception = new ZkpException(errorMessage, cause);

        assertEquals(errorMessage, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }
}