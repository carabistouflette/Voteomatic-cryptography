package com.voteomatic.cryptography.io;

/**
 * A specialized DataHandler interface for securely storing and retrieving
 * cryptographic key material.
 * <p>
 * Implementations of this interface are expected to handle key data with
 * appropriate security measures (e.g., encryption at rest, access controls).
 * It inherits the basic read/write operations from DataHandler but signals
 * a specific purpose.
 */
public interface KeyStorageHandler extends DataHandler {

    // This interface can be extended with key-specific methods if needed,
    // for example, methods that handle specific key formats or metadata.
    // For now, it acts as a specialized marker inheriting DataHandler methods.

    /**
     * Example of a potential future method:
     * Checks if key data exists at the specified location.
     *
     * @param keyIdentifier The identifier for the key data.
     * @return true if key data exists, false otherwise.
     * @throws DataHandlingException if checking existence fails.
     */
    // boolean keyExists(String keyIdentifier) throws DataHandlingException;

}