package com.voteomatic.cryptography.core.zkp;

/**
 * Custom exception class for errors occurring during Zero-Knowledge Proof generation or
 * verification.
 */
public class ZkpException extends Exception {

  /**
   * Constructs a new ZkpException with the specified detail message.
   *
   * @param message the detail message.
   */
  public ZkpException(String message) {
    super(message);
  }

  /**
   * Constructs a new ZkpException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   *     (A {@code null} value is permitted, and indicates that the cause is nonexistent or
   *     unknown.)
   */
  public ZkpException(String message, Throwable cause) {
    super(message, cause);
  }
}
