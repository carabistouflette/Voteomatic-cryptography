package com.voteomatic.cryptography.securityutils;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SecurityUtilExceptionTest {

  private static final String TEST_MESSAGE = "Test exception message";
  private static final Throwable TEST_CAUSE = new RuntimeException("Root cause");

  @Test
  void constructor_withMessage_setsMessageCorrectly() {
    SecurityUtilException exception = new SecurityUtilException(TEST_MESSAGE);
    assertEquals(TEST_MESSAGE, exception.getMessage());
    assertNull(exception.getCause(), "Cause should be null when only message is provided");
  }

  @Test
  void constructor_withNullMessage_setsMessageToNull() {
    SecurityUtilException exception = new SecurityUtilException(null);
    assertNull(exception.getMessage());
    assertNull(exception.getCause());
  }

  @Test
  void constructor_withMessageAndCause_setsBothCorrectly() {
    SecurityUtilException exception = new SecurityUtilException(TEST_MESSAGE, TEST_CAUSE);
    assertEquals(TEST_MESSAGE, exception.getMessage());
    assertEquals(TEST_CAUSE, exception.getCause(), "Cause should be set correctly");
  }

  @Test
  void constructor_withNullMessageAndCause_setsBothToNull() {
    SecurityUtilException exception = new SecurityUtilException(null, null);
    assertNull(exception.getMessage());
    assertNull(exception.getCause());
  }

  @Test
  void constructor_withMessageAndNullCause_setsMessageCorrectlyCauseNull() {
    SecurityUtilException exception = new SecurityUtilException(TEST_MESSAGE, null);
    assertEquals(TEST_MESSAGE, exception.getMessage());
    assertNull(exception.getCause(), "Cause should be null when explicitly passed as null");
  }

  @Test
  void constructor_withNullMessageAndNonNullCause_setsMessageNullCauseCorrectly() {
    SecurityUtilException exception = new SecurityUtilException(null, TEST_CAUSE);
    assertNull(exception.getMessage());
    assertEquals(
        TEST_CAUSE, exception.getCause(), "Cause should be set correctly even with null message");
  }
}
