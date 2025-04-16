package com.voteomatic.cryptography.keymanagement;

/**
 * Custom exception class for errors occurring during key management operations (generation,
 * storage, retrieval).
 */
public class KeyManagementException extends Exception {

  /**
   * Constructs a new KeyManagementException with the specified detail message.
   *
   * @param message the detail message.
   */
  public KeyManagementException(String message) {
    super(message);
  }

  /**
   * Constructs a new KeyManagementException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause the cause.
   */
  public KeyManagementException(String message, Throwable cause) {
    super(message, cause);
  }
}
