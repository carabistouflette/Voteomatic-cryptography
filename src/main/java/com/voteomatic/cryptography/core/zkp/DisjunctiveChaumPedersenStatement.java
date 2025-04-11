package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the public statement for a Disjunctive Chaum-Pedersen proof,
 * specifically tailored for proving that an ElGamal ciphertext encrypts
 * one of two known messages (e.g., g^0 or g^1).
 *
 * Statement: We know the private randomness 'r' and message index 'v' such that
 * c1 = g^r AND ( (v=0 AND c2 = m0 * h^r) OR (v=1 AND c2 = m1 * h^r) )
 */
public class DisjunctiveChaumPedersenStatement implements Statement {

    private final BigInteger p; // Group modulus
    private final BigInteger g; // Group generator
    private final BigInteger h; // Public key value (y in ElGamal)
    private final BigInteger c1; // Ciphertext component 1 (g^r)
    private final BigInteger c2; // Ciphertext component 2 (m * h^r)
    private final BigInteger m0; // Possible message 0 (e.g., g^0 = 1)
    private final BigInteger m1; // Possible message 1 (e.g., g^1 = g)

    public DisjunctiveChaumPedersenStatement(PublicKey publicKey, Ciphertext ciphertext, BigInteger m0, BigInteger m1) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(m0, "Message m0 cannot be null");
        Objects.requireNonNull(m1, "Message m1 cannot be null");

        this.p = publicKey.getP();
        this.g = publicKey.getG();
        this.h = publicKey.getY();
        this.c1 = ciphertext.getC1();
        this.c2 = ciphertext.getC2();
        this.m0 = m0;
        this.m1 = m1;

        // Basic validation (could add more checks)
        if (p == null || g == null || h == null || c1 == null || c2 == null) {
            throw new IllegalArgumentException("Public key or ciphertext components cannot be null");
        }
    }

    // Getters for all fields
    public BigInteger getP() { return p; }
    public BigInteger getG() { return g; }
    public BigInteger getH() { return h; }
    public BigInteger getC1() { return c1; }
    public BigInteger getC2() { return c2; }
    public BigInteger getM0() { return m0; }
    public BigInteger getM1() { return m1; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DisjunctiveChaumPedersenStatement that = (DisjunctiveChaumPedersenStatement) o;
        return Objects.equals(p, that.p) &&
               Objects.equals(g, that.g) &&
               Objects.equals(h, that.h) &&
               Objects.equals(c1, that.c1) &&
               Objects.equals(c2, that.c2) &&
               Objects.equals(m0, that.m0) &&
               Objects.equals(m1, that.m1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, g, h, c1, c2, m0, m1);
    }

    @Override
    public String toString() {
        return "DisjunctiveChaumPedersenStatement{" +
               "p=" + p +
               ", g=" + g +
               ", h=" + h +
               ", c1=" + c1 +
               ", c2=" + c2 +
               ", m0=" + m0 +
               ", m1=" + m1 +
               '}';
    }
}