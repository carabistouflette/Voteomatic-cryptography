package com.voteomatic.cryptography.securityutils;

/**
 * Marker interface for a private key used for generating digital signatures.
 * Concrete implementations will hold the specific key material for a given
 * signature algorithm (e.g., RSA private exponent, ECDSA private value).
 * It should be kept confidential.
 */
public interface PrivateSigningKey {
    // Marker interface - details depend on the specific signature algorithm.

    /**
     * Gets the standard algorithm name associated with this key (e.g., "RSA", "ECDSA").
     *
     * @return The algorithm name.
     */
    String getAlgorithm();
}