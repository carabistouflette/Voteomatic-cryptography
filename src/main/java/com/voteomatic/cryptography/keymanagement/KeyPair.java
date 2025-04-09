package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import java.util.Objects;

/**
 * Represents a pair of ElGamal public and private keys.
 * Simple container class.
 */
public class KeyPair {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    /**
     * Constructs a KeyPair.
     *
     * @param publicKey The public key. Must not be null.
     * @param privateKey The private key. Must not be null.
     */
    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        // Optional: Add validation that keys belong together (e.g., check p, g)
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyPair keyPair = (KeyPair) o;
        return publicKey.equals(keyPair.publicKey) && privateKey.equals(keyPair.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }
}