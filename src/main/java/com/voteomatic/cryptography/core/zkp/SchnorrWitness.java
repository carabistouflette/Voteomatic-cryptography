package com.voteomatic.cryptography.core.zkp;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the secret witness for Schnorr's protocol. Contains the secret value (discrete
 * logarithm) such that y = g^x mod p.
 */
public class SchnorrWitness implements Witness {

  private final BigInteger secretValue; // Renamed from x

  /**
   * Private constructor for SchnorrWitness. Validation is done in the factory method.
   *
   * @param secretValue The validated secret value.
   */
  private SchnorrWitness(BigInteger secretValue) {
    this.secretValue = secretValue; // Assumed non-null by factory method
    // Basic validation could be added here (e.g., x is in the correct range [0, q-1])
    // For simplicity, we assume valid inputs.
  }

  /**
   * Creates a SchnorrWitness instance.
   *
   * @param secretValue The secret value (discrete logarithm). Must not be null.
   * @return A new SchnorrWitness instance.
   * @throws IllegalArgumentException if secretValue is null.
   */
  public static SchnorrWitness create(BigInteger secretValue) {
    if (secretValue == null) {
      throw new IllegalArgumentException("Witness parameter secretValue cannot be null");
    }
    return new SchnorrWitness(secretValue);
  }

  public BigInteger getSecretValue() { // Renamed from getX
    return secretValue;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) { // Added braces
      return true;
    }
    if (o == null || getClass() != o.getClass()) { // Added braces
      return false;
    }
    SchnorrWitness that = (SchnorrWitness) o;
    return Objects.equals(secretValue, that.secretValue); // Use renamed variable
  }

  @Override
  public int hashCode() {
    return Objects.hash(secretValue); // Use renamed variable
  }

  @Override
  public String toString() {
    // Avoid logging the secret value directly in production environments
    return "SchnorrWitness{secretValue=HIDDEN}"; // Use renamed variable (optional, kept hidden)
  }
}
