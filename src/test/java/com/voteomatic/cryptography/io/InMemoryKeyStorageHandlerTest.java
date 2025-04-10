package com.voteomatic.cryptography.io;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryKeyStorageHandlerTest {

    private KeyStorageHandler storageHandler;

    @BeforeEach
    void setUp() {
        storageHandler = new InMemoryKeyStorageHandler();
    }

    @Test
    void testWriteAndReadData_Success() throws DataHandlingException {
        String identifier = "test-data-1";
        byte[] originalData = "This is test data.".getBytes();

        // Write data
        storageHandler.writeData(identifier, originalData);

        // Read data
        byte[] retrievedData = storageHandler.readData(identifier);

        // Verify
        assertNotNull(retrievedData, "Retrieved data should not be null");
        assertArrayEquals(originalData, retrievedData, "Retrieved data should match original data");
    }

    @Test
    void testReadData_NotFound() {
        String identifier = "non-existent-data";

        // Attempt to read data that hasn't been written
        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.readData(identifier);
        }, "Should throw DataHandlingException when data is not found");

        assertEquals("No data found for identifier: " + identifier, exception.getMessage());
    }

    @Test
    void testWriteData_OverwriteExisting() throws DataHandlingException {
        String identifier = "overwrite-test";
        byte[] initialData = "Initial data".getBytes();
        byte[] newData = "New overwritten data".getBytes();

        // Write initial data
        storageHandler.writeData(identifier, initialData);
        byte[] retrievedInitial = storageHandler.readData(identifier);
        assertArrayEquals(initialData, retrievedInitial, "Initial data retrieval failed");

        // Write new data (overwrite)
        storageHandler.writeData(identifier, newData);
        byte[] retrievedNew = storageHandler.readData(identifier);

        // Verify new data
        assertNotNull(retrievedNew, "Retrieved overwritten data should not be null");
        assertArrayEquals(newData, retrievedNew, "Retrieved data should match the overwritten data");
    }

    @Test
    void testWriteData_NullIdentifier() {
        byte[] data = "Some data".getBytes();

        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.writeData(null, data);
        }, "Should throw DataHandlingException for null identifier");

        assertEquals("Identifier cannot be null or empty.", exception.getMessage());
    }

    @Test
    void testWriteData_EmptyIdentifier() {
        byte[] data = "Some data".getBytes();

        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.writeData("  ", data); // Whitespace only
        }, "Should throw DataHandlingException for empty identifier");

        assertEquals("Identifier cannot be null or empty.", exception.getMessage());
    }

    @Test
    void testWriteData_NullData() {
        String identifier = "null-data-test";

        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.writeData(identifier, null);
        }, "Should throw DataHandlingException for null data");

        assertEquals("Data cannot be null.", exception.getMessage());
    }

    @Test
    void testReadData_NullIdentifier() {
        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.readData(null);
        }, "Should throw DataHandlingException for null identifier");

        assertEquals("Identifier cannot be null or empty.", exception.getMessage());
    }

    @Test
    void testReadData_EmptyIdentifier() {
        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            storageHandler.readData(""); // Empty string
        }, "Should throw DataHandlingException for empty identifier");

        assertEquals("Identifier cannot be null or empty.", exception.getMessage());
    }

     @Test
    void testWriteAndRead_EmptyData() throws DataHandlingException {
        String identifier = "empty-data-test";
        byte[] emptyData = new byte[0];

        storageHandler.writeData(identifier, emptyData);
        byte[] retrievedData = storageHandler.readData(identifier);

        assertNotNull(retrievedData, "Retrieved data should not be null even if empty");
        assertArrayEquals(emptyData, retrievedData, "Retrieved empty data should match original empty data");
    }
}