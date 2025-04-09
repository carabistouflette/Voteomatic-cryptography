package com.voteomatic.cryptography.core.elgamal;

import java.math.BigInteger;
import java.io.Serializable;
import java.util.Objects;

/**
 * Represents an ElGamal private key.
 * Contains the public parameters (p, g) and the private exponent x.
 * It's often useful to include p and g for context during decryption.
 */
public class PrivateKey implements Serializable {
    private static final long serialVersionUID = 1L; // Add serialVersionUID for Serializable classes
    private final BigInteger p; // Prime modulus (same as in PublicKey)
    private final BigInteger g; // Generator (same as in PublicKey)
    private final BigInteger x; // Private exponent

    /**
     * Constructs an ElGamal PrivateKey.
     *
     * @param p The prime modulus. Must be non-null.
     * @param g The generator. Must be non-null.
     * @param x The private exponent. Must be non-null.
     */
    public PrivateKey(BigInteger p, BigInteger g, BigInteger x) {
        Objects.requireNonNull(p, "Prime modulus p cannot be null");
        Objects.requireNonNull(g, "Generator g cannot be null");
        Objects.requireNonNull(x, "Private exponent x cannot be null");
        // Basic validation could be added here
        this.p = p;
        this.g = g;
        this.x = x;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getX() {
        return x;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrivateKey that = (PrivateKey) o;
        // Note: Equality usually only depends on 'x' for a given set of parameters (p, g)
        // but including p and g makes the object self-contained for comparison.
        return p.equals(that.p) && g.equals(that.g) && x.equals(that.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, g, x);
    }

    @Override
    public String toString() {
        // Avoid logging the actual private key 'x' directly in production logs
        return "PrivateKey{" +
               "p=" + p +
               ", g=" + g +
               ", x=[REDACTED]" +
               '}';
    }
}