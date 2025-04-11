package com.voteomatic.cryptography.io;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * Interface for securely storing and retrieving cryptographic key pairs and public keys.
 * Implementations handle the specifics of the storage mechanism (e.g., file, database, hardware).
 */
public interface KeyStorageHandler {

    /**
     * Stores a key pair along with its associated certificate, protected by a password.
     *
     * @param alias       A unique identifier for the key pair within the storage.
     * @param keyPair     The {@link java.security.KeyPair} to store.
     * @param certificate The {@link java.security.cert.Certificate} associated with the public key.
     *                    Often a self-signed certificate is sufficient if no CA is involved.
     * @param password    The password to protect the key pair entry.
     * @throws DataHandlingException if storing the key pair fails.
     */
    void storeKeyPair(String alias, KeyPair keyPair, Certificate certificate, char[] password) throws DataHandlingException;

    /**
     * Retrieves a key pair from storage using its alias and password.
     *
     * @param alias    The unique identifier for the key pair.
     * @param password The password required to access the key pair.
     * @return The retrieved {@link java.security.KeyPair}.
     * @throws DataHandlingException if retrieving the key pair fails (e.g., alias not found, incorrect password).
     */
    KeyPair retrieveKeyPair(String alias, char[] password) throws DataHandlingException;

    /**
     * Retrieves only the public key associated with a given alias.
     * This typically does not require a password.
     *
     * @param alias The unique identifier for the key entry.
     * @return The retrieved {@link java.security.PublicKey}.
     * @throws DataHandlingException if retrieving the public key fails (e.g., alias not found).
     */
    PublicKey getPublicKey(String alias) throws DataHandlingException;

    // Optional: Consider adding methods like keyExists(String alias) or listAliases() in the future.
}