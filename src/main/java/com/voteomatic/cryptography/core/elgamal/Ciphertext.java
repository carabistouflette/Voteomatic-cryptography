package com.voteomatic.cryptography.core.elgamal;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents an ElGamal ciphertext. Typically consists of two components: c1 = g^k mod p and c2 = m
 * * y^k mod p, where k is a random exponent.
 */
public class Ciphertext implements Serializable {

  private static final long serialVersionUID = 1L;

  private final BigInteger c1; // Component 1 (g^k mod p)
  private final BigInteger c2; // Component 2 (m * y^k mod p)

  /**
   * Constructs an ElGamal Ciphertext.
   *
   * @param c1 The first component of the ciphertext.
   * @param c2 The second component of the ciphertext.
   */
  public Ciphertext(BigInteger c1, BigInteger c2) {
    // Null checks removed to allow testing of downstream null handling
    this.c1 = c1;
    this.c2 = c2;
  }

  public BigInteger getC1() {
    return c1;
  }

  public BigInteger getC2() {
    return c2;
  }

  /**
   * Multiplies this ciphertext with another ciphertext component-wise modulo p. This operation
   * corresponds to the addition of the underlying plaintexts in ElGamal.
   *
   * @param other The other ciphertext to multiply with.
   * @param p The modulus from the public key parameters.
   * @return A new Ciphertext representing the product.
   * @throws NullPointerException if other or p is null, or if any ciphertext component is null.
   */
  public Ciphertext multiply(Ciphertext other, BigInteger p) {
    Objects.requireNonNull(other, "Other ciphertext cannot be null");
    Objects.requireNonNull(p, "Modulus p cannot be null");
    Objects.requireNonNull(this.c1, "This ciphertext's c1 cannot be null");
    Objects.requireNonNull(this.c2, "This ciphertext's c2 cannot be null");
    Objects.requireNonNull(other.c1, "Other ciphertext's c1 cannot be null");
    Objects.requireNonNull(other.c2, "Other ciphertext's c2 cannot be null");

    if (p.compareTo(BigInteger.ONE) <= 0) {
      throw new IllegalArgumentException("Modulus p must be greater than 1");
    }

    BigInteger newC1 = this.c1.multiply(other.c1).mod(p);
    BigInteger newC2 = this.c2.multiply(other.c2).mod(p);

    return new Ciphertext(newC1, newC2);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Ciphertext that = (Ciphertext) o;
    // Adjusted equals to handle potential nulls introduced by removing constructor checks
    return Objects.equals(c1, that.c1) && Objects.equals(c2, that.c2);
  }

  @Override
  public int hashCode() {
    // Adjusted hashCode to handle potential nulls
    return Objects.hash(c1, c2);
  }

  @Override
  public String toString() {
    return "Ciphertext{" + "c1=" + c1 + ", c2=" + c2 + '}';
  }
}
