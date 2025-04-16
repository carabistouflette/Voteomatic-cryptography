package com.voteomatic.cryptography.io;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class DataHandlingExceptionTest {

  private static final String TEST_MESSAGE = "Test data handling error";
  private static final Throwable TEST_CAUSE = new RuntimeException("Root cause exception");

  @Test
  void testConstructorWithMessage() {
    DataHandlingException exception = new DataHandlingException(TEST_MESSAGE);

    assertEquals(
        TEST_MESSAGE,
        exception.getMessage(),
        "Exception message should match the one provided in the constructor.");
    assertNull(exception.getCause(), "Cause should be null when only message is provided.");
  }

  @Test
  void testConstructorWithMessageAndCause() {
    DataHandlingException exception = new DataHandlingException(TEST_MESSAGE, TEST_CAUSE);

    assertEquals(TEST_MESSAGE, exception.getMessage(), "Exception message should match.");
    assertNotNull(exception.getCause(), "Cause should not be null.");
    assertEquals(TEST_CAUSE, exception.getCause(), "Cause should match the one provided.");
  }

  @Test
  void testConstructorWithNullMessage() {
    // Check if the constructor handles null message gracefully (it should inherit behavior from
    // Exception)
    DataHandlingException exception = new DataHandlingException(null, TEST_CAUSE);
    assertNull(exception.getMessage(), "Message should be null if null is passed.");
    assertEquals(
        TEST_CAUSE, exception.getCause(), "Cause should still be set even with null message.");
  }

  @Test
  void testConstructorWithNullCause() {
    // Check if the constructor handles null cause gracefully
    DataHandlingException exception = new DataHandlingException(TEST_MESSAGE, null);
    assertEquals(TEST_MESSAGE, exception.getMessage(), "Message should be set correctly.");
    assertNull(exception.getCause(), "Cause should be null if null is passed.");
  }

  @Test
  void testConstructorWithNullMessageAndNullCause() {
    // Check behavior with both nulls
    DataHandlingException exception = new DataHandlingException(null, null);
    assertNull(exception.getMessage(), "Message should be null.");
    assertNull(exception.getCause(), "Cause should be null.");
  }
}
