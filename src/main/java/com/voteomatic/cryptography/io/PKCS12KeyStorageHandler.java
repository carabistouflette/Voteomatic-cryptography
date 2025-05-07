package com.voteomatic.cryptography.io;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of {@link KeyStorageHandler} that persists key pairs securely in a
 * password-protected PKCS12 KeyStore file.
 *
 * <p>This handler stores standard {@link java.security.KeyPair} objects along with their associated
 * {@link java.security.cert.Certificate} chain.
 */
public class PKCS12KeyStorageHandler implements KeyStorageHandler {

  private static final Logger LOGGER = Logger.getLogger(PKCS12KeyStorageHandler.class.getName());
  private static final String KEYSTORE_TYPE = "PKCS12";

  private final Path keystorePath;
  private final char[] keystorePassword;
  private final Object lock = new Object(); // For synchronizing write access

  /** Private constructor used by factory methods. */
  private PKCS12KeyStorageHandler(Path keystorePath, char[] password) {
    this.keystorePath = keystorePath;
    this.keystorePassword = password; // Assume password was cloned by factory if needed
    LOGGER.log(Level.INFO, "PKCS12KeyStorageHandler initialized for path: {0}", this.keystorePath);
  }

  /**
   * Creates a PKCS12KeyStorageHandler using a password retrieved from an environment variable.
   *
   * @param keystorePathStr The path to the PKCS12 keystore file.
   * @param passwordSource A string indicating how to retrieve the password (e.g.,
   *     "env:KEYSTORE_PASSWORD"). Currently, only "env:VAR_NAME" is supported.
   * @return A new PKCS12KeyStorageHandler instance.
   * @throws DataHandlingException If the password cannot be retrieved or the path is invalid.
   */
  public static PKCS12KeyStorageHandler createFromEnvPassword(
      String keystorePathStr, String passwordSource) throws DataHandlingException {
    Objects.requireNonNull(keystorePathStr, "Keystore path cannot be null");
    Objects.requireNonNull(passwordSource, "Password source cannot be null");

    char[] retrievedPassword = retrievePassword(passwordSource); // Might throw
    Path path = Paths.get(keystorePathStr);
    validatePathAndCreateDirs(path, keystorePathStr); // Might throw

    return new PKCS12KeyStorageHandler(path, retrievedPassword);
  }

  /**
   * Creates a PKCS12KeyStorageHandler using a direct password.
   *
   * @param keystorePathStr The path to the PKCS12 keystore file.
   * @param password The password for the keystore. Must not be null. The provided array will be
   *     cloned for security.
   * @return A new PKCS12KeyStorageHandler instance.
   * @throws DataHandlingException If the path is invalid or permissions are insufficient.
   */
  public static PKCS12KeyStorageHandler createWithPassword(String keystorePathStr, char[] password)
      throws DataHandlingException {
    Objects.requireNonNull(keystorePathStr, "Keystore path cannot be null");
    Objects.requireNonNull(password, "Keystore password cannot be null");

    Path path = Paths.get(keystorePathStr);
    char[] clonedPassword = password.clone(); // Clone for security
    validatePathAndCreateDirs(path, keystorePathStr); // Might throw

    // Clear original password array immediately after cloning if possible (best effort)
    java.util.Arrays.fill(password, '\0');

    return new PKCS12KeyStorageHandler(path, clonedPassword);
  }

  /** Helper method to validate path and create parent directories. */
  private static void validatePathAndCreateDirs(Path path, String originalPathStr)
      throws DataHandlingException {
    try {
      Path parentDir = path.getParent();
      if (parentDir != null && !Files.isDirectory(parentDir)) {
        Files.createDirectories(parentDir); // Might throw
        LOGGER.log(Level.INFO, "Created parent directory for keystore: {0}", parentDir);
      }
    } catch (IOException | SecurityException e) {
      throw new DataHandlingException(
          "Invalid keystore path or permissions issue: " + originalPathStr, e);
    }
  }

  private static char[] retrievePassword(String passwordSource) throws DataHandlingException {
    if (passwordSource.startsWith("env:")) {
      String envVarName = passwordSource.substring(4);
      String password = System.getenv(envVarName);
      if (password == null || password.isEmpty()) {
        throw new DataHandlingException(
            "Keystore password environment variable '" + envVarName + "' not set or empty.");
      }
      return password.toCharArray();
    } else {
      // TODO: Extend later for other sources (e.g., file, config)
      throw new DataHandlingException(
          "Unsupported password source format: " + passwordSource + ". Use 'env:VAR_NAME'.");
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
        LOGGER.log(
            Level.INFO, "Keystore file not found at {0}, initializing new keystore.", keystorePath);
      }
      return keyStore;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      // Check for specific password error (often manifests as IOException)
      if (e instanceof IOException
          && e.getMessage() != null
          && (e.getMessage().contains("password was incorrect")
              || e.getMessage().contains("mac check failed"))) {
        throw new DataHandlingException(
            "Failed to load keystore: Incorrect password provided for " + keystorePath, e);
      }
      throw new DataHandlingException("Failed to load or initialize keystore: " + keystorePath, e);
    }
  }

  private void saveKeyStore(KeyStore keyStore) throws DataHandlingException {
    // Atomic save: write to temp file, then rename
    Path tempPath = null;
    try {
      Path parentDir = keystorePath.getParent();
      // Use current directory if parent is null (e.g., keystore is in root)
      Path tempDir = (parentDir != null) ? parentDir : Paths.get(".");
      Path fileNamePath = keystorePath.getFileName();
      String prefix =
          (fileNamePath != null) ? fileNamePath.toString() : "keystore"; // Provide default prefix
      tempPath = Files.createTempFile(tempDir, prefix, ".tmp");
      try (OutputStream os = new FileOutputStream(tempPath.toFile())) {
        // FileOutputStream constructor throws an exception if it fails, so os is guaranteed
        // non-null here.
        keyStore.store(os, keystorePassword);
      }
      // Set file permissions if possible (e.g., owner read/write only) - platform dependent
      try {
        Files.setPosixFilePermissions(
            tempPath, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
      } catch (UnsupportedOperationException | IOException | SecurityException e) {
        LOGGER.log(
            Level.WARNING,
            "Could not set restrictive file permissions on keystore temp file (may not be supported"
                + " on this OS): "
                + tempPath,
            e);
      }

      Files.move(
          tempPath,
          keystorePath,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
      LOGGER.log(Level.FINE, "Saved keystore to: {0}", keystorePath);

    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      // Clean up temp file on failure
      if (tempPath != null) {
        try {
          Files.deleteIfExists(tempPath);
        } catch (IOException cleanupEx) {
          LOGGER.log(
              Level.SEVERE,
              "Failed to delete temporary keystore file after save error: " + tempPath,
              cleanupEx);
        }
      }
      throw new DataHandlingException("Failed to save keystore: " + keystorePath, e);
    }
  }

  @Override
  public void storeKeyPair(String alias, KeyPair keyPair, Certificate certificate, char[] password)
      throws DataHandlingException {
    Objects.requireNonNull(alias, "Alias cannot be null");
    Objects.requireNonNull(keyPair, "KeyPair cannot be null");
    Objects.requireNonNull(keyPair.getPrivate(), "Private key in KeyPair cannot be null");
    Objects.requireNonNull(certificate, "Certificate cannot be null");
    Objects.requireNonNull(
        password, "Password cannot be null"); // Password for the key entry itself

    LOGGER.log(Level.INFO, "Attempting to store key pair for alias: {0}", alias);

    // The certificate chain usually contains just the single certificate for the key pair
    Certificate[] certificateChain = {certificate};

    // Synchronize writes to prevent race conditions when modifying the file
    synchronized (lock) {
      KeyStore keyStore = loadKeyStore(); // Load fresh copy before modification
      try {
        // Store the private key and its certificate chain
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, certificateChain);
        saveKeyStore(keyStore); // Save the updated keystore
        LOGGER.log(Level.INFO, "Successfully stored key pair for alias: {0}", alias);
      } catch (KeyStoreException e) {
        throw new DataHandlingException(
            "Failed to set key entry in keystore for alias: " + alias, e);
      }
    }
  }

  @Override
  public KeyPair retrieveKeyPair(String alias, char[] password) throws DataHandlingException {
    Objects.requireNonNull(alias, "Alias cannot be null");
    Objects.requireNonNull(password, "Password cannot be null");
    LOGGER.log(Level.INFO, "Attempting to retrieve key pair for alias: {0}", alias);

    KeyStore keyStore = loadKeyStore();
    try {
      // Check if the alias exists first
      if (!keyStore.containsAlias(alias)) {
        LOGGER.log(Level.WARNING, "Alias not found in keystore: {0}", alias);
        throw new DataHandlingException("Alias not found in keystore: " + alias);
      }

      // Check if it's a key entry
      if (!keyStore.isKeyEntry(alias)) {
        LOGGER.log(Level.SEVERE, "Entry for alias {0} is not a key entry.", alias);
        throw new DataHandlingException(
            "Keystore entry for alias '" + alias + "' is not a key entry.");
      }

      // Retrieve the private key
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);

      // Retrieve the corresponding certificate to get the public key
      Certificate certificate = keyStore.getCertificate(alias);
      if (certificate == null) {
        // This shouldn't happen if setKeyEntry was used correctly, but check defensively
        LOGGER.log(
            Level.SEVERE,
            "Certificate not found for alias {0}, although private key exists.",
            alias);
        throw new DataHandlingException(
            "Certificate not found for alias '" + alias + "' in keystore.");
      }
      PublicKey publicKey = certificate.getPublicKey();

      LOGGER.log(Level.INFO, "Successfully retrieved key pair for alias: {0}", alias);
      return new KeyPair(publicKey, privateKey);

    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      // UnrecoverableKeyException often indicates incorrect password
      if (e instanceof UnrecoverableKeyException) {
        LOGGER.log(
            Level.WARNING,
            "Failed to retrieve key for alias {0}: Incorrect password or corrupted key.",
            alias);
        throw new DataHandlingException(
            "Failed to retrieve key for alias '" + alias + "': Incorrect password provided.", e);
      }
      throw new DataHandlingException(
          "Failed to retrieve key entry from keystore for alias: " + alias, e);
    } catch (ClassCastException e) {
      // Should not happen if isKeyEntry check passes and storage was correct
      LOGGER.log(Level.SEVERE, "Retrieved key for alias {0} was not a PrivateKey.", alias);
      throw new DataHandlingException(
          "Retrieved key for alias '" + alias + "' was not of the expected type (PrivateKey).", e);
    }
  }

  @Override
  public PublicKey getPublicKey(String alias) throws DataHandlingException {
    Objects.requireNonNull(alias, "Alias cannot be null");
    LOGGER.log(Level.INFO, "Attempting to retrieve public key for alias: {0}", alias);

    KeyStore keyStore = loadKeyStore();
    try {
      // Check if the alias exists first
      if (!keyStore.containsAlias(alias)) {
        LOGGER.log(Level.WARNING, "Alias not found in keystore: {0}", alias);
        throw new DataHandlingException("Alias not found in keystore: " + alias);
      }

      // Retrieve the certificate associated with the alias
      Certificate certificate = keyStore.getCertificate(alias);
      if (certificate == null) {
        // This could happen if it's a trusted certificate entry, not a key entry
        LOGGER.log(
            Level.WARNING,
            "No certificate found for alias {0}. It might not be a key pair entry.",
            alias);
        throw new DataHandlingException(
            "No certificate found for alias '" + alias + "'. Cannot retrieve public key.");
      }

      PublicKey publicKey = certificate.getPublicKey();
      LOGGER.log(Level.INFO, "Successfully retrieved public key for alias: {0}", alias);
      return publicKey;

    } catch (KeyStoreException e) {
      throw new DataHandlingException(
          "Failed to retrieve certificate from keystore for alias: " + alias, e);
    }
  }
}
