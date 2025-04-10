package com.voteomatic.cryptography.voting;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class VotingExceptionTest {

    @Test
    void testConstructorWithMessage() {
        String errorMessage = "Test error message";
        VotingException exception = new VotingException(errorMessage);
        assertEquals(errorMessage, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testConstructorWithMessageAndCause() {
        String errorMessage = "Test error message with cause";
        Throwable cause = new RuntimeException("Root cause");
        VotingException exception = new VotingException(errorMessage, cause);
        assertEquals(errorMessage, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void testConstructorWithNullMessage() {
        VotingException exception = new VotingException(null);
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testConstructorWithNullMessageAndCause() {
        Throwable cause = new RuntimeException("Root cause");
        VotingException exception = new VotingException(null, cause);
        // Standard behavior is null message if passed null, even with a cause
        assertNull(exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void testConstructorWithMessageAndNullCause() {
        String errorMessage = "Test error message with null cause";
        VotingException exception = new VotingException(errorMessage, null);
        assertEquals(errorMessage, exception.getMessage());
        assertNull(exception.getCause());
    }
}