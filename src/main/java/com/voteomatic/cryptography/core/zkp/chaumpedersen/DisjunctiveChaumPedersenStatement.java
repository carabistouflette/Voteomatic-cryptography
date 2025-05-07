package com.voteomatic.cryptography.core.zkp.chaumpedersen;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.Statement;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the public statement for a Disjunctive Chaum-Pedersen proof, specifically tailored for
 * proving that an ElGamal ciphertext encrypts one of two known messages (e.g., g^0 or g^1).
 *
 * <p>Statement: We know the private randomness 'r' and message index 'v' such that c1 = g^r AND (
 * (v=0 AND c2 = m0 * h^r) OR (v=1 AND c2 = m1 * h^r) )
 */
public class DisjunctiveChaumPedersenStatement implements Statement {

  private final DomainParameters params; // Group parameters (p, g, q)
  private final BigInteger h; // Public key value (y in ElGamal)
  private final BigInteger c1; // Ciphertext component 1 (g^r)
  private final BigInteger c2; // Ciphertext component 2 (m * h^r)
  private final BigInteger m0; // Possible message 0 (e.g., g^0 = 1)
  private final BigInteger m1; // Possible message 1 (e.g., g^1 = g)

  /**
   * Private constructor. Validation is performed in the factory method.
   *
   * @param params Validated DomainParameters.
   * @param h Validated public key value.
   * @param c1 Validated ciphertext component 1.
   * @param c2 Validated ciphertext component 2.
   * @param m0 Validated possible message 0.
   * @param m1 Validated possible message 1.
   */
  private DisjunctiveChaumPedersenStatement(
      DomainParameters params,
      BigInteger h,
      BigInteger c1,
      BigInteger c2,
      BigInteger m0,
      BigInteger m1) {
    this.params = params;
    this.h = h;
    this.c1 = c1;
    this.c2 = c2;
    this.m0 = m0;
    this.m1 = m1;
  }

  /**
   * Creates a DisjunctiveChaumPedersenStatement instance.
   *
   * @param publicKey The public key associated with the ciphertext. Must not be null.
   * @param ciphertext The ElGamal ciphertext. Must not be null.
   * @param m0 The first possible message (e.g., g^0). Must not be null.
   * @param m1 The second possible message (e.g., g^1). Must not be null.
   * @return A new DisjunctiveChaumPedersenStatement instance.
   * @throws IllegalArgumentException if any parameter or derived component is null.
   */
  public static DisjunctiveChaumPedersenStatement create(
      PublicKey publicKey, Ciphertext ciphertext, BigInteger m0, BigInteger m1) {
    Objects.requireNonNull(publicKey, "Public key cannot be null");
    Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
    Objects.requireNonNull(m0, "Message m0 cannot be null");
    Objects.requireNonNull(m1, "Message m1 cannot be null");

    DomainParameters params = publicKey.getParams();
    BigInteger h = publicKey.getY();
    BigInteger c1 = ciphertext.getC1();
    BigInteger c2 = ciphertext.getC2();

    // Validation: Ensure necessary components are present
    if (params == null || h == null || c1 == null || c2 == null) {
      throw new IllegalArgumentException(
          "DomainParameters, public key value (h), or ciphertext components cannot be null");
    }

    return new DisjunctiveChaumPedersenStatement(params, h, c1, c2, m0, m1);
  }

  // Getters for all fields
  public BigInteger getP() {
    return params.getP();
  }

  public BigInteger getG() {
    return params.getG();
  }

  public BigInteger getQ() {
    return params.getQ();
  }

  public DomainParameters getParams() {
    return params;
  }

  public BigInteger getH() {
    return h;
  }

  public BigInteger getC1() {
    return c1;
  }

  public BigInteger getC2() {
    return c2;
  }

  public BigInteger getM0() {
    return m0;
  }

  public BigInteger getM1() {
    return m1;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DisjunctiveChaumPedersenStatement that = (DisjunctiveChaumPedersenStatement) o;
    return Objects.equals(params, that.params)
        && Objects.equals(h, that.h)
        && Objects.equals(c1, that.c1)
        && Objects.equals(c2, that.c2)
        && Objects.equals(m0, that.m0)
        && Objects.equals(m1, that.m1);
  }

  @Override
  public int hashCode() {
    return Objects.hash(params, h, c1, c2, m0, m1);
  }

  @Override
  public String toString() {
    return "DisjunctiveChaumPedersenStatement{"
        + "params="
        + params
        + ", h="
        + h
        + ", c1="
        + c1
        + ", c2="
        + c2
        + ", m0="
        + m0
        + ", m1="
        + m1
        + '}';
  }
}
