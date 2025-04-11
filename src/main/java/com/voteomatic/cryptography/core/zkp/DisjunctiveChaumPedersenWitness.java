package com.voteomatic.cryptography.core.zkp;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the secret witness for a Disjunctive Chaum-Pedersen proof,
 * specifically for proving knowledge of the randomness 'r' and the index 'v'
 * corresponding to the actual encrypted message (either m0 or m1).
 */
public class DisjunctiveChaumPedersenWitness implements Witness {

    private final BigInteger r; // The randomness used in ElGamal encryption (c1 = g^r, c2 = m*h^r)
    private final int v;        // The index of the true message (0 if m0 was encrypted, 1 if m1 was encrypted)

    /**
     * Constructs a witness.
     *
     * @param r The ElGamal encryption randomness. Must not be null.
     * @param v The index of the actual encrypted message (must be 0 or 1).
     */
    public DisjunctiveChaumPedersenWitness(BigInteger r, int v) {
        Objects.requireNonNull(r, "Randomness r cannot be null");
        if (v != 0 && v != 1) {
            throw new IllegalArgumentException("Message index v must be 0 or 1");
        }
        this.r = r;
        this.v = v;
    }

    public BigInteger getR() {
        return r;
    }

    public int getV() {
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DisjunctiveChaumPedersenWitness that = (DisjunctiveChaumPedersenWitness) o;
        return v == that.v && Objects.equals(r, that.r);
    }

    @Override
    public int hashCode() {
        return Objects.hash(r, v);
    }

    @Override
    public String toString() {
        // Avoid logging secret witness values in production
        return "DisjunctiveChaumPedersenWitness{" +
               "r=[secret]" +
               ", v=" + v +
               '}';
    }
}