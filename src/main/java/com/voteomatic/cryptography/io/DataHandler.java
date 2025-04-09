package com.voteomatic.cryptography.io;

/**
 * Generic interface for abstracting data input/output operations.
 * Defines contracts for reading and writing raw byte data from/to specified locations
 * (which could represent file paths, network endpoints, database keys, etc.).
 */
public interface DataHandler {

    /**
     * Writes the given byte data to a specified destination.
     * The interpretation of 'destination' depends on the implementation (e.g., file path).
     *
     * @param destination A string identifying where to write the data.
     * @param data        The byte array containing the data to write. Must not be null.
     * @throws DataHandlingException if writing the data fails (e.g., IO error, invalid destination).
     */
    void writeData(String destination, byte[] data) throws DataHandlingException;

    /**
     * Reads byte data from a specified source.
     * The interpretation of 'source' depends on the implementation (e.g., file path).
     *
     * @param source A string identifying where to read the data from.
     * @return A byte array containing the data read from the source.
     * @throws DataHandlingException if reading the data fails (e.g., source not found, IO error).
     */
    byte[] readData(String source) throws DataHandlingException;
}