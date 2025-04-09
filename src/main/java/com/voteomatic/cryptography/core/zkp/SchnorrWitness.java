package com.voteomatic.cryptography.core.zkp;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the secret witness for Schnorr's protocol.
 * Contains the secret value x such that y = g^x mod p.
 */
public class SchnorrWitness implements Witness {

    private final BigInteger x;

    /**
     * Constructs a SchnorrWitness.
     *
     * @param x The secret value (discrete logarithm).
     * @throws IllegalArgumentException if x is null.
     */
    public SchnorrWitness(BigInteger x) {
        if (x == null) {
            throw new IllegalArgumentException("Witness parameter x cannot be null");
        }
        // Basic validation could be added here (e.g., x is in the correct range [0, q-1])
        // For simplicity, we assume valid inputs.
        this.x = x;
    }

    public BigInteger getX() {
        return x;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchnorrWitness that = (SchnorrWitness) o;
        return Objects.equals(x, that.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x);
    }

    @Override
    public String toString() {
        // Avoid logging the secret value directly in production environments
        return "SchnorrWitness{x=HIDDEN}";
    }
}