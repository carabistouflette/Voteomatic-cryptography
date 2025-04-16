package com.voteomatic.cryptography.securityutils;

/**
 * Custom exception class for errors occurring within security utility operations (hashing, signing,
 * random number generation).
 */
public class SecurityUtilException extends Exception {

  /**
   * Constructs a new SecurityUtilException with the specified detail message.
   *
   * @param message the detail message.
   */
  public SecurityUtilException(String message) {
    super(message);
  }

  /**
   * Constructs a new SecurityUtilException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause the cause.
   */
  public SecurityUtilException(String message, Throwable cause) {
    super(message, cause);
  }
}
