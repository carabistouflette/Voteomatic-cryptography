package com.voteomatic.cryptography.io;

/**
 * Custom exception class for errors occurring during data input/output operations (reading/writing
 * keys, votes, etc.).
 */
public class DataHandlingException extends Exception {

  /**
   * Constructs a new DataHandlingException with the specified detail message.
   *
   * @param message the detail message.
   */
  public DataHandlingException(String message) {
    super(message);
  }

  /**
   * Constructs a new DataHandlingException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause the cause (often an underlying java.io.IOException).
   */
  public DataHandlingException(String message, Throwable cause) {
    super(message, cause);
  }
}
