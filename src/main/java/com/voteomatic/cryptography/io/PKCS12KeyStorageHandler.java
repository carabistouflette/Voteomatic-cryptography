package com.voteomatic.cryptography.io;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of KeyStorageHandler that persists keys securely in a
 * password-protected PKCS12 KeyStore file.
 *
 * Assumes the caller handles serialization/deserialization of the actual KeyPair
 * objects into/from the byte arrays passed to writeData/readData.
 */
public class PKCS12KeyStorageHandler implements KeyStorageHandler {

    private static final Logger LOGGER = Logger.getLogger(PKCS12KeyStorageHandler.class.getName());
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String SECRET_KEY_ALGORITHM = "AES"; // Algorithm name for SecretKeySpec wrapper

    private final Path keystorePath;
    private final char[] keystorePassword;
    private final Object lock = new Object(); // For synchronizing write access

    /**
     * Constructs a PKCS12KeyStorageHandler.
     *
     * @param keystorePathStr The path to the PKCS12 keystore file.
     * @param passwordSource A string indicating how to retrieve the password (e.g., "env:KEYSTORE_PASSWORD").
     *                       Currently, only "env:VAR_NAME" is supported.
     * @throws DataHandlingException If the password cannot be retrieved or the path is invalid.
     */
    public PKCS12KeyStorageHandler(String keystorePathStr, String passwordSource) throws DataHandlingException {
        Objects.requireNonNull(keystorePathStr, "Keystore path cannot be null");
        Objects.requireNonNull(passwordSource, "Password source cannot be null");

        this.keystorePath = Paths.get(keystorePathStr);
        this.keystorePassword = retrievePassword(passwordSource);

        // Basic validation of path
        try {
            // Ensure parent directory exists if possible
            Path parentDir = this.keystorePath.getParent();
            if (parentDir != null && !Files.isDirectory(parentDir)) {
                 Files.createDirectories(parentDir);
                 LOGGER.log(Level.INFO, "Created parent directory for keystore: {0}", parentDir);
            }
        } catch (IOException | SecurityException e) {
            throw new DataHandlingException("Invalid keystore path or permissions issue: " + keystorePathStr, e);
        }

        LOGGER.log(Level.INFO, "PKCS12KeyStorageHandler initialized for path: {0}", this.keystorePath);
    }

    /**
     * Constructs a PKCS12KeyStorageHandler with a direct password.
     *
     * @param keystorePathStr The path to the PKCS12 keystore file.
     * @param password        The password for the keystore. Must not be null.
     * @throws DataHandlingException If the path is invalid or permissions are insufficient.
     */
    public PKCS12KeyStorageHandler(String keystorePathStr, char[] password) throws DataHandlingException {
        Objects.requireNonNull(keystorePathStr, "Keystore path cannot be null");
        Objects.requireNonNull(password, "Keystore password cannot be null");

        this.keystorePath = Paths.get(keystorePathStr);
        // Consider cloning the password array for security if needed: this.keystorePassword = password.clone();
        this.keystorePassword = password;

        // Basic validation of path
        try {
            // Ensure parent directory exists if possible
            Path parentDir = this.keystorePath.getParent();
            if (parentDir != null && !Files.isDirectory(parentDir)) {
                 Files.createDirectories(parentDir);
                 LOGGER.log(Level.INFO, "Created parent directory for keystore: {0}", parentDir);
            }
        } catch (IOException | SecurityException e) {
            throw new DataHandlingException("Invalid keystore path or permissions issue: " + keystorePathStr, e);
        }

        LOGGER.log(Level.INFO, "PKCS12KeyStorageHandler initialized for path: {0}", this.keystorePath);
    }

    private char[] retrievePassword(String passwordSource) throws DataHandlingException {
        if (passwordSource.startsWith("env:")) {
            String envVarName = passwordSource.substring(4);
            String password = System.getenv(envVarName);
            if (password == null || password.isEmpty()) {
                throw new DataHandlingException("Keystore password environment variable '" + envVarName + "' not set or empty.");
            }
            return password.toCharArray();
        } else {
            // Extend later for other sources (e.g., file, config)
            throw new DataHandlingException("Unsupported password source format: " + passwordSource + ". Use 'env:VAR_NAME'.");
        }
    }

    private KeyStore loadKeyStore() throws DataHandlingException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            if (Files.exists(keystorePath)) {
                try (InputStream is = new FileInputStream(keystorePath.toFile())) {
                    keyStore.load(is, keystorePassword);
                    LOGGER.log(Level.FINE, "Loaded existing keystore from: {0}", keystorePath);
                }
            } else {
                // Initialize empty keystore if file doesn't exist
                keyStore.load(null, keystorePassword);
                LOGGER.log(Level.INFO, "Keystore file not found at {0}, initializing new keystore.", keystorePath);
            }
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            // Check for specific password error (often manifests as IOException)
             if (e instanceof IOException && e.getMessage() != null && (e.getMessage().contains("password was incorrect") || e.getMessage().contains("mac check failed"))) {
                 throw new DataHandlingException("Failed to load keystore: Incorrect password provided for " + keystorePath, e);
             }
            throw new DataHandlingException("Failed to load or initialize keystore: " + keystorePath, e);
        }
    }

    private void saveKeyStore(KeyStore keyStore) throws DataHandlingException {
        // Atomic save: write to temp file, then rename
        Path tempPath = null;
        try {
            tempPath = Files.createTempFile(keystorePath.getParent(), keystorePath.getFileName().toString(), ".tmp");
            try (OutputStream os = new FileOutputStream(tempPath.toFile())) {
                keyStore.store(os, keystorePassword);
            }
            // Set file permissions if possible (e.g., owner read/write only) - platform dependent
            try {
                 Files.setPosixFilePermissions(tempPath, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException | IOException | SecurityException e) {
                 LOGGER.log(Level.WARNING, "Could not set restrictive file permissions on keystore temp file (may not be supported on this OS): " + tempPath, e);
            }

            Files.move(tempPath, keystorePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            LOGGER.log(Level.FINE, "Saved keystore to: {0}", keystorePath);

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            // Clean up temp file on failure
            if (tempPath != null) {
                try {
                    Files.deleteIfExists(tempPath);
                } catch (IOException cleanupEx) {
                    LOGGER.log(Level.SEVERE, "Failed to delete temporary keystore file after save error: " + tempPath, cleanupEx);
                }
            }
            throw new DataHandlingException("Failed to save keystore: " + keystorePath, e);
        }
    }


    @Override
    public void writeData(String alias, byte[] data) throws DataHandlingException {
        Objects.requireNonNull(alias, "Alias cannot be null");
        Objects.requireNonNull(data, "Data cannot be null");

        LOGGER.log(Level.INFO, "Attempting to write data for alias: {0}", alias);

        // Wrap raw bytes into a SecretKey suitable for SecretKeyEntry
        SecretKey secretKey = new SecretKeySpec(data, SECRET_KEY_ALGORITHM);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);

        // Synchronize writes to prevent race conditions when modifying the file
        synchronized (lock) {
            KeyStore keyStore = loadKeyStore(); // Load fresh copy before modification
            try {
                keyStore.setEntry(alias, entry, protectionParam);
                saveKeyStore(keyStore);
                LOGGER.log(Level.INFO, "Successfully wrote data for alias: {0}", alias);
            } catch (KeyStoreException e) {
                throw new DataHandlingException("Failed to set entry in keystore for alias: " + alias, e);
            }
        }
    }

    @Override
    public byte[] readData(String alias) throws DataHandlingException {
         Objects.requireNonNull(alias, "Alias cannot be null");
         LOGGER.log(Level.INFO, "Attempting to read data for alias: {0}", alias);

         // Reads can potentially be concurrent if KeyStore object isn't modified,
         // but loading from file is simpler and safer for now.
         KeyStore keyStore = loadKeyStore();
         try {
             KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);
             KeyStore.Entry entry = keyStore.getEntry(alias, protectionParam);

             if (entry == null) {
                 LOGGER.log(Level.WARNING, "Alias not found in keystore: {0}", alias);
                 throw new DataHandlingException("Alias not found in keystore: " + alias);
             }

             if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                  LOGGER.log(Level.SEVERE, "Entry for alias {0} is not a SecretKeyEntry (unexpected type: {1})", new Object[]{alias, entry.getClass().getName()});
                 throw new DataHandlingException("Keystore entry for alias '" + alias + "' is not of the expected type (SecretKeyEntry).");
             }

             KeyStore.SecretKeyEntry secretEntry = (KeyStore.SecretKeyEntry) entry;
             SecretKey secretKey = secretEntry.getSecretKey();

             if (!SECRET_KEY_ALGORITHM.equals(secretKey.getAlgorithm())) {
                 LOGGER.log(Level.SEVERE, "SecretKey algorithm mismatch for alias {0}. Expected {1}, found {2}", new Object[]{alias, SECRET_KEY_ALGORITHM, secretKey.getAlgorithm()});
                 throw new DataHandlingException("SecretKey algorithm mismatch for alias '" + alias + "'. Data may be corrupted or stored incorrectly.");
             }

             byte[] data = secretKey.getEncoded();
             LOGGER.log(Level.INFO, "Successfully read data for alias: {0}", alias);
             return data;

         } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
             throw new DataHandlingException("Failed to retrieve entry from keystore for alias: " + alias, e);
         }
    }
}