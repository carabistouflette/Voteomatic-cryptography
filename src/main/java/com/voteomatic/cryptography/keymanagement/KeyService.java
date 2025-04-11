package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PublicKey;

/**
 * Interface for managing cryptographic keys (generation, storage, retrieval).
 * Defines the contract for services responsible for the lifecycle of keys.
 */
public interface KeyService {

    /**
     * Generates a new ElGamal key pair based on configured parameters.
     *
     * @return The newly generated KeyPair.
     * @throws KeyManagementException if key generation fails.
     */
    KeyPair generateKeyPair() throws KeyManagementException;

    /**
     * Stores a key pair, associating it with a unique identifier.
     * The underlying implementation should handle secure storage.
     *
     * @param keyPair    The KeyPair to store.
     * @param identifier A unique identifier (alias) for the key pair.
     * @param password   The password to protect the key entry in the underlying storage.
     * @throws KeyManagementException if storing the key fails (e.g., identifier collision, storage error).
     */
    void storeKeyPair(KeyPair keyPair, String identifier, char[] password) throws KeyManagementException;

    /**
     * Retrieves a previously stored key pair using its identifier.
     *
     * @param identifier The unique identifier (alias) of the key pair to retrieve.
     * @param password   The password required to access the key entry in the underlying storage.
     * @return The retrieved KeyPair.
     * @throws KeyManagementException if the key pair is not found, the password is incorrect, or retrieval fails.
     */
    KeyPair retrieveKeyPair(String identifier, char[] password) throws KeyManagementException;

    /**
     * Retrieves only the public key associated with a given identifier.
     * This is often needed without exposing the private key.
     *
     * @param identifier The unique identifier of the key pair.
     * @return The corresponding PublicKey.
     * @throws KeyManagementException if the key pair is not found or retrieval fails.
     */
    PublicKey getPublicKey(String identifier) throws KeyManagementException;

    /**
     * Optional: Verifies the integrity or properties of a public key.
     * This could involve checking if parameters (p, g) are valid or if the key
     * belongs to a specific group. Implementation details depend on requirements.
     *
     * @param publicKey The public key to verify.
     * @return true if the key is considered valid, false otherwise.
     * @throws KeyManagementException if verification encounters an error.
     */
    boolean verifyKeyIntegrity(PublicKey publicKey) throws KeyManagementException;
}