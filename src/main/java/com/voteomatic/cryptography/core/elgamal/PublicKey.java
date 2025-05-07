package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.core.DomainParameters;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents an ElGamal public key. Contains the domain parameters and the public value y = g^x mod
 * p.
 */
public class PublicKey {
  private final DomainParameters params; // Domain parameters (p, g, q)
  private final BigInteger y; // Public value (g^x mod p)

  /**
   * Constructs an ElGamal PublicKey.
   *
   * @param params The domain parameters (p, g, q). Must be non-null.
   * @param y The public value y = g^x mod p. Must be non-null.
   */
  public PublicKey(DomainParameters params, BigInteger y) {
    this.params = Objects.requireNonNull(params, "DomainParameters cannot be null");
    this.y = Objects.requireNonNull(y, "Public value y cannot be null");
    // Basic validation could be added here (e.g., check if y is in the correct range/subgroup)
  }

  /**
   * Gets the prime modulus p from the domain parameters.
   *
   * @return The prime modulus p.
   */
  public BigInteger getP() {
    return params.getP();
  }

  /**
   * Gets the generator g from the domain parameters.
   *
   * @return The generator g.
   */
  public BigInteger getG() {
    return params.getG();
  }

  /**
   * Gets the prime subgroup order q from the domain parameters.
   *
   * @return The prime subgroup order q.
   */
  public BigInteger getQ() {
    return params.getQ();
  }

  /**
   * Gets the full domain parameters object.
   *
   * @return The DomainParameters object containing p, g, and q.
   */
  public DomainParameters getParams() {
    return params;
  }

  public BigInteger getY() {
    return y;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PublicKey publicKey = (PublicKey) o;
    return params.equals(publicKey.params) && y.equals(publicKey.y);
  }

  @Override
  public int hashCode() {
    return Objects.hash(params, y);
  }

  @Override
  public String toString() {
    // Delegate parameter details to DomainParameters.toString()
    return "PublicKey{" + "params=" + params + ", y=" + y + '}';
  }
}
