package com.voteomatic.cryptography.core.elgamal;

import java.math.BigInteger;
import java.io.Serializable;
import java.util.Objects;

/**
 * Represents an ElGamal public key.
 * Contains the public parameters (p, g) and the public value y = g^x mod p.
 */
public class PublicKey implements Serializable {
    private static final long serialVersionUID = 1L; // Add serialVersionUID for Serializable classes
    private final BigInteger p; // Prime modulus
    private final BigInteger g; // Generator
    private final BigInteger y; // Public value (g^x mod p)

    /**
     * Constructs an ElGamal PublicKey.
     *
     * @param p The prime modulus. Must be non-null.
     * @param g The generator. Must be non-null.
     * @param y The public value y. Must be non-null.
     */
    public PublicKey(BigInteger p, BigInteger g, BigInteger y) {
        Objects.requireNonNull(p, "Prime modulus p cannot be null");
        Objects.requireNonNull(g, "Generator g cannot be null");
        Objects.requireNonNull(y, "Public value y cannot be null");
        // Basic validation could be added here (e.g., check if p is prime, g is generator)
        this.p = p;
        this.g = g;
        this.y = y;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getY() {
        return y;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKey publicKey = (PublicKey) o;
        return p.equals(publicKey.p) && g.equals(publicKey.g) && y.equals(publicKey.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, g, y);
    }

    @Override
    public String toString() {
        return "PublicKey{" +
               "p=" + p +
               ", g=" + g +
               ", y=" + y +
               '}';
    }
}