package com.voteomatic.cryptography.io;

import java.util.HashMap;
import java.util.Map;

/**
 * A simple in-memory implementation of KeyStorageHandler.
 * Data stored using this handler is not persistent and will be lost
 * when the application stops.
 */
public class InMemoryKeyStorageHandler implements KeyStorageHandler {

    private final Map<String, byte[]> storage = new HashMap<>();

    /**
     * Stores the given data associated with the specified identifier.
     * If data already exists for the identifier, it will be overwritten.
     *
     * @param identifier The unique identifier for the data.
     * @param data       The byte array data to store.
     * @throws DataHandlingException If an error occurs during storage (though unlikely for in-memory).
     */
    @Override
    public void writeData(String identifier, byte[] data) throws DataHandlingException {
        if (identifier == null || identifier.trim().isEmpty()) {
            throw new DataHandlingException("Identifier cannot be null or empty.");
        }
        if (data == null) {
            throw new DataHandlingException("Data cannot be null.");
        }
        // In-memory storage is straightforward, but could add checks if needed.
        storage.put(identifier, data);
    }

    /**
     * Retrieves the data associated with the specified identifier.
     *
     * @param identifier The unique identifier for the data to retrieve.
     * @return A byte array containing the data read from the source.
     * @throws DataHandlingException If an error occurs during retrieval or if the identifier is not found.
     */
    @Override
    public byte[] readData(String identifier) throws DataHandlingException {
        if (identifier == null || identifier.trim().isEmpty()) {
            throw new DataHandlingException("Identifier cannot be null or empty.");
        }
        byte[] data = storage.get(identifier);
        if (data == null) {
            throw new DataHandlingException("No data found for identifier: " + identifier);
        }
        return data;
    }

}