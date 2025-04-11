package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.core.DomainParameters; // Added import

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents an ElGamal private key.
 * Contains the domain parameters and the private exponent x.
 */
public class PrivateKey {
    private final DomainParameters params; // Domain parameters (p, g, q)
    private final BigInteger x;          // Private exponent

    /**
     * Constructs an ElGamal PrivateKey.
     *
     * @param params The domain parameters (p, g, q). Must be non-null.
     * @param x      The private exponent. Must be non-null.
     */
    public PrivateKey(DomainParameters params, BigInteger x) {
        this.params = Objects.requireNonNull(params, "DomainParameters cannot be null");
        this.x = Objects.requireNonNull(x, "Private exponent x cannot be null");
        // Basic validation could be added here (e.g., check if x is in the range [1, q-1])
    }

    /**
     * Gets the prime modulus p from the domain parameters.
     * @return The prime modulus p.
     */
    public BigInteger getP() {
        return params.getP();
    }

    /**
     * Gets the generator g from the domain parameters.
     * @return The generator g.
     */
    public BigInteger getG() {
        return params.getG();
    }

    /**
     * Gets the prime subgroup order q from the domain parameters.
     * @return The prime subgroup order q.
     */
    public BigInteger getQ() {
        return params.getQ();
    }

    /**
     * Gets the full domain parameters object.
     * @return The DomainParameters object containing p, g, and q.
     */
    public DomainParameters getParams() {
        return params;
    }

    public BigInteger getX() {
        return x;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrivateKey that = (PrivateKey) o;
        // Equality depends on both the parameters and the private exponent.
        return params.equals(that.params) && x.equals(that.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(params, x);
    }

    @Override
    public String toString() {
        // Avoid logging the actual private key 'x' directly in production logs
        // Delegate parameter details to DomainParameters.toString()
        return "PrivateKey{" +
               "params=" + params +
               ", x=[REDACTED]" +
               '}';
    }
}