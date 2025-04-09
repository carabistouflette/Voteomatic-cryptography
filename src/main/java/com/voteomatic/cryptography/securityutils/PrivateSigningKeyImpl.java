package com.voteomatic.cryptography.securityutils;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * A concrete implementation of PrivateSigningKey, wrapping a standard java.security.PrivateKey.
 */
public class PrivateSigningKeyImpl implements PrivateSigningKey {

    private final PrivateKey privateKey;

    /**
     * Constructs a PrivateSigningKeyImpl.
     *
     * @param privateKey The underlying java.security.PrivateKey. Must not be null.
     */
    public PrivateSigningKeyImpl(PrivateKey privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "PrivateKey cannot be null.");
    }

    /**
     * Gets the underlying JCA PrivateKey object.
     * This method provides access to the raw key material needed by underlying JCA providers.
     *
     * @return The java.security.PrivateKey instance.
     */
    public PrivateKey getJcaPrivateKey() {
        return privateKey;
    }

    @Override
    public String getAlgorithm() {
        return privateKey.getAlgorithm();
    }

    // Note: equals() and hashCode() are not implemented. Comparison relies on object identity.
    // Consider implementing them if needed for collections or comparisons based on key material.
}