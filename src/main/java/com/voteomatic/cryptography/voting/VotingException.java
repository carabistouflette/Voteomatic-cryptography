package com.voteomatic.cryptography.voting;

/**
 * Custom exception class for errors occurring during voting protocol operations (casting, tallying,
 * verification).
 */
public class VotingException extends Exception {

  /**
   * Constructs a new VotingException with the specified detail message.
   *
   * @param message the detail message.
   */
  public VotingException(String message) {
    super(message);
  }

  /**
   * Constructs a new VotingException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause the cause.
   */
  public VotingException(String message, Throwable cause) {
    super(message, cause);
  }
}
