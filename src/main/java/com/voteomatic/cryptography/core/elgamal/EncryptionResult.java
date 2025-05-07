package com.voteomatic.cryptography.core.elgamal;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Holds the result of an ElGamal encryption operation, including the ciphertext and the randomness
 * used.
 */
public class EncryptionResult {

  private final Ciphertext ciphertext;
  private final BigInteger randomness; // The random value 'r' used in encryption (g^r, m*h^r)

  /**
   * Constructs an EncryptionResult.
   *
   * @param ciphertext The generated ElGamal ciphertext. Must not be null.
   * @param randomness The random value 'r' used during encryption. Must not be null.
   */
  public EncryptionResult(Ciphertext ciphertext, BigInteger randomness) {
    this.ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
    this.randomness = Objects.requireNonNull(randomness, "Randomness cannot be null");
  }

  public Ciphertext getCiphertext() {
    return ciphertext;
  }

  public BigInteger getRandomness() {
    return randomness;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    EncryptionResult that = (EncryptionResult) o;
    return Objects.equals(ciphertext, that.ciphertext)
        && Objects.equals(randomness, that.randomness);
  }

  @Override
  public int hashCode() {
    return Objects.hash(ciphertext, randomness);
  }

  @Override
  public String toString() {
    return "EncryptionResult{"
        + "ciphertext="
        + ciphertext
        + ", randomness="
        + randomness
        + // Be cautious about logging randomness in production
        '}';
  }
}
