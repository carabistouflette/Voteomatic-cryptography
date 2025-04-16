package com.voteomatic.cryptography.io;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

// Tests involving environment variables require setup before running tests.
// Example:
// export TEST_KEYSTORE_PASSWORD_ENV='envPassword123'
// export TEST_KEYSTORE_PASSWORD_ENV_EMPTY=''
// export TEST_KEYSTORE_PASSWORD_ENV_WRONG='wrongEnvPassword'
//
// @DisabledIfEnvironmentVariable annotations were previously used but commented out.
// Using Assumptions.assumeTrue() provides a way to skip tests if variables aren't set,
// preventing failures in environments without the necessary setup.
// Temporarily disable env var check for easier local testing if needed, re-enable for CI.
class PKCS12KeyStorageHandlerTest {

  // Static initializer to register BouncyCastle provider
  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  // Use fixed passwords for tests for simplicity, avoiding env var dependency during refactoring
  private static final char[] KEYSTORE_PASSWORD = "testpassword".toCharArray();
  private static final char[] WRONG_KEYSTORE_PASSWORD = "wrongpassword".toCharArray();
  private static final char[] KEY_ENTRY_PASSWORD =
      "keypassword".toCharArray(); // Password for the key entry itself
  private static final String KEYSTORE_TYPE = "PKCS12"; // Define for use in tests

  // Environment variable names used in tests
  private static final String TEST_PASSWORD_ENV_VAR = "TEST_KEYSTORE_PASSWORD_ENV";
  private static final String TEST_PASSWORD_ENV_EMPTY_VAR = "TEST_KEYSTORE_PASSWORD_ENV_EMPTY";
  private static final String TEST_PASSWORD_ENV_WRONG_VAR = "TEST_KEYSTORE_PASSWORD_ENV_WRONG";
  private static final String PASSWORD_SOURCE_VALID = "env:" + TEST_PASSWORD_ENV_VAR;
  private static final String PASSWORD_SOURCE_EMPTY = "env:" + TEST_PASSWORD_ENV_EMPTY_VAR;
  private static final String PASSWORD_SOURCE_WRONG =
      "env:" + TEST_PASSWORD_ENV_WRONG_VAR; // For testing load failure with env var password
  // private static final String WRONG_PASSWORD_SOURCE = "env:" + TEST_WRONG_PASSWORD_ENV_VAR;

  private static KeyPair testKeyPair;
  private static X509Certificate testCertificate;

  @TempDir Path tempDir;

  private Path keystorePath;
  private PKCS12KeyStorageHandler handler;

  // Generate KeyPair and Certificate once for all tests
  @BeforeAll
  static void generateTestData()
      throws NoSuchAlgorithmException,
          CertificateException,
          OperatorCreationException,
          IOException {
    testKeyPair = generateTestingKeyPair();
    testCertificate = generateSelfSignedCertificate(testKeyPair, "CN=Test Cert, O=Voteomatic Test");
    // Add BouncyCastle provider if not already added
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
  }

  @BeforeEach
  void setUp() throws DataHandlingException {
    // Use fixed passwords for setup
    keystorePath = tempDir.resolve("testkeystore.p12");
    // Ensure keystore file doesn't exist from previous runs within the same @Test method execution
    try {
      Files.deleteIfExists(keystorePath);
    } catch (IOException e) {
      throw new RuntimeException("Failed to delete test keystore before setup", e);
    }
    handler =
        PKCS12KeyStorageHandler.createWithPassword(keystorePath.toString(), KEYSTORE_PASSWORD);
  }

  // Helper method to generate a KeyPair
  private static KeyPair generateTestingKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048); // Use a standard key size
    return keyGen.generateKeyPair();
  }

  // Helper method to generate a self-signed X.509 Certificate using BouncyCastle
  private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN)
      throws CertificateException, OperatorCreationException, IOException {

    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();
    Instant now = Instant.now();
    Date validityBeginDate = Date.from(now);
    Date validityEndDate = Date.from(now.plus(365, ChronoUnit.DAYS)); // 1 year validity

    X500Name owner = new X500Name(subjectDN);
    BigInteger serialNumber = new BigInteger(64, new SecureRandom()); // Random serial number

    // Use BouncyCastle builder
    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            owner, // Issuer DN (same as subject for self-signed)
            serialNumber, // Serial number
            validityBeginDate, // Not before
            validityEndDate, // Not after
            owner, // Subject DN
            publicKey); // Public key

    // Sign the certificate using the private key
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256WithRSA") // Use appropriate algorithm
            .setProvider("BC") // Specify BouncyCastle provider
            .build(privateKey);

    // Build and return the certificate
    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certBuilder.build(signer));
  }

  @Test
  void testStoreAndRetrieveKeyPair() throws DataHandlingException {
    String alias = "testAlias";

    // Store key pair
    handler.storeKeyPair(alias, testKeyPair, testCertificate, KEY_ENTRY_PASSWORD);

    // Verify file exists
    assertTrue(Files.exists(keystorePath), "Keystore file should be created after store.");

    // Retrieve key pair back
    KeyPair retrievedKeyPair = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);

    assertNotNull(retrievedKeyPair, "Retrieved key pair should not be null.");
    assertEquals(
        testKeyPair.getPublic(),
        retrievedKeyPair.getPublic(),
        "Retrieved public key should match original.");
    assertEquals(
        testKeyPair.getPrivate(),
        retrievedKeyPair.getPrivate(),
        "Retrieved private key should match original.");

    // Also test getPublicKey
    PublicKey retrievedPublicKey = handler.getPublicKey(alias);
    assertNotNull(
        retrievedPublicKey, "Retrieved public key (via getPublicKey) should not be null.");
    assertEquals(
        testKeyPair.getPublic(),
        retrievedPublicKey,
        "Retrieved public key (via getPublicKey) should match original.");
  }

  @Test
  void testRetrieveNonExistentAlias() {
    String alias = "nonExistentAlias";

    // Attempt to retrieve non-existent alias
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
            },
            "Retrieving non-existent alias should throw DataHandlingException.");

    assertTrue(
        exception.getMessage().contains("Alias not found"),
        "Exception message should indicate alias not found.");

    // Also test getPublicKey for non-existent alias
    DataHandlingException pubKeyException =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handler.getPublicKey(alias);
            },
            "Getting public key for non-existent alias should throw DataHandlingException.");

    assertTrue(
        pubKeyException.getMessage().contains("Alias not found"),
        "Public key exception message should indicate alias not found.");
  }

  @Test
  void testOverwriteExistingKeyPair()
      throws DataHandlingException,
          NoSuchAlgorithmException,
          CertificateException,
          OperatorCreationException,
          IOException {
    String alias = "overwriteAlias";
    KeyPair initialKeyPair = testKeyPair; // Use the globally generated one
    Certificate initialCertificate = testCertificate;

    // Generate a new keypair and certificate for overwriting
    KeyPair updatedKeyPair = generateTestingKeyPair();
    Certificate updatedCertificate =
        generateSelfSignedCertificate(updatedKeyPair, "CN=Updated Test Cert");

    // Store initial key pair
    handler.storeKeyPair(alias, initialKeyPair, initialCertificate, KEY_ENTRY_PASSWORD);
    KeyPair retrievedInitial = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
    assertEquals(
        initialKeyPair.getPublic(),
        retrievedInitial.getPublic(),
        "Initial retrieved public key should match.");
    assertEquals(
        initialKeyPair.getPrivate(),
        retrievedInitial.getPrivate(),
        "Initial retrieved private key should match.");

    // Store updated key pair (overwrite)
    handler.storeKeyPair(alias, updatedKeyPair, updatedCertificate, KEY_ENTRY_PASSWORD);
    KeyPair retrievedUpdated = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
    assertEquals(
        updatedKeyPair.getPublic(),
        retrievedUpdated.getPublic(),
        "Updated retrieved public key should match.");
    assertEquals(
        updatedKeyPair.getPrivate(),
        retrievedUpdated.getPrivate(),
        "Updated retrieved private key should match.");
    assertNotEquals(
        initialKeyPair.getPublic(),
        retrievedUpdated.getPublic(),
        "Updated public key should differ from initial.");
  }

  @Test
  void testInitializationCreatesDirectory() throws IOException, DataHandlingException {
    Path deepPath = tempDir.resolve("subdir1/subdir2/deepkeystore.p12");
    // Ensure parent directories do not exist initially
    Files.deleteIfExists(deepPath);
    if (deepPath.getParent() != null) {
      Files.deleteIfExists(deepPath.getParent());
      if (deepPath.getParent().getParent() != null) {
        Files.deleteIfExists(deepPath.getParent().getParent());
      }
    }

    assertFalse(
        Files.exists(deepPath.getParent()),
        "Parent directory should not exist before initialization.");

    // Initialize handler with a path requiring directory creation
    PKCS12KeyStorageHandler.createWithPassword(deepPath.toString(), KEYSTORE_PASSWORD);

    assertTrue(
        Files.exists(deepPath.getParent()),
        "Parent directory should be created during initialization.");
  }

  // This test verifies that loading the *keystore* with the wrong password fails.
  @Test
  void testLoadKeystoreWithIncorrectPassword() throws DataHandlingException {
    String alias = "testAlias";
    // Store something first using the correct keystore password
    handler.storeKeyPair(alias, testKeyPair, testCertificate, KEY_ENTRY_PASSWORD);

    // Create a handler instance using the incorrect keystore password
    PKCS12KeyStorageHandler handlerWithWrongPassword =
        PKCS12KeyStorageHandler.createWithPassword(
            keystorePath.toString(), WRONG_KEYSTORE_PASSWORD);

    // Attempt to retrieve (which triggers loading the keystore) should fail
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handlerWithWrongPassword.retrieveKeyPair(
                  alias,
                  KEY_ENTRY_PASSWORD); // Password here is for the key entry, but load fails first
            },
            "Retrieving with incorrect keystore password should throw DataHandlingException during"
                + " load.");

    // The exception message comes from loadKeyStore()
    assertTrue(
        exception.getMessage().contains("Incorrect password")
            || (exception.getCause() != null
                && exception.getCause().getMessage().contains("mac check failed")),
        "Exception message should indicate incorrect keystore password or MAC failure during load."
            + " Message: "
            + exception.getMessage());
  }

  // This test verifies that retrieving a key *entry* with the wrong password fails,
  // assuming the keystore itself was loaded correctly.
  @Test
  void testRetrieveKeyWithIncorrectEntryPassword() throws DataHandlingException {
    String alias = "testAlias";
    char[] wrongEntryPassword = "wrongKeyPassword".toCharArray();
    // Store using the correct keystore password and the correct entry password
    handler.storeKeyPair(alias, testKeyPair, testCertificate, KEY_ENTRY_PASSWORD);

    // Attempt to retrieve using the correct keystore password handler, but the wrong entry password
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handler.retrieveKeyPair(alias, wrongEntryPassword);
            },
            "Retrieving with incorrect key entry password should throw DataHandlingException.");

    // The exception message comes from retrieveKeyPair() -> keyStore.getKey()
    assertTrue(
        exception
            .getMessage()
            .contains("Incorrect password provided"), // Check specific message from retrieveKeyPair
        "Exception message should indicate incorrect key entry password. Message: "
            + exception.getMessage());
  }

  @Test
  void testStoreMultipleKeyPairs()
      throws DataHandlingException,
          NoSuchAlgorithmException,
          CertificateException,
          OperatorCreationException,
          IOException {
    String alias1 = "entry1";
    KeyPair keyPair1 = testKeyPair; // Reuse main one
    Certificate cert1 = testCertificate;

    String alias2 = "entry2";
    KeyPair keyPair2 = generateTestingKeyPair(); // Generate a second distinct pair
    Certificate cert2 = generateSelfSignedCertificate(keyPair2, "CN=Entry 2");

    handler.storeKeyPair(alias1, keyPair1, cert1, KEY_ENTRY_PASSWORD);
    handler.storeKeyPair(alias2, keyPair2, cert2, KEY_ENTRY_PASSWORD);

    KeyPair retrieved1 = handler.retrieveKeyPair(alias1, KEY_ENTRY_PASSWORD);
    KeyPair retrieved2 = handler.retrieveKeyPair(alias2, KEY_ENTRY_PASSWORD);

    assertEquals(keyPair1.getPublic(), retrieved1.getPublic());
    assertEquals(keyPair1.getPrivate(), retrieved1.getPrivate());
    assertEquals(keyPair2.getPublic(), retrieved2.getPublic());
    assertEquals(keyPair2.getPrivate(), retrieved2.getPrivate());
  }

  // Basic thread safety check - multiple threads writing different aliases
  // Note: This is a basic check; more rigorous concurrency testing might be needed.
  @Test
  void testConcurrentStores() throws InterruptedException {
    int numThreads = 5;
    Thread[] threads = new Thread[numThreads];
    final boolean[] failures = new boolean[numThreads];
    final KeyPair[] threadKeyPairs = new KeyPair[numThreads];
    final Certificate[] threadCertificates = new Certificate[numThreads];

    // Pre-generate keypairs/certs outside the threads to avoid concurrency issues there
    for (int i = 0; i < numThreads; i++) {
      try {
        threadKeyPairs[i] = generateTestingKeyPair();
        threadCertificates[i] =
            generateSelfSignedCertificate(threadKeyPairs[i], "CN=Concurrent " + i);
      } catch (Exception e) {
        fail("Failed to generate test data for concurrency test: " + e.getMessage());
      }
    }

    for (int i = 0; i < numThreads; i++) {
      final int index = i;
      final KeyPair kp = threadKeyPairs[index];
      final Certificate cert = threadCertificates[index];
      threads[i] =
          new Thread(
              () -> {
                try {
                  String alias = "concurrentAlias_" + index;
                  // Use a unique password per entry if needed, or reuse KEY_ENTRY_PASSWORD
                  handler.storeKeyPair(alias, kp, cert, KEY_ENTRY_PASSWORD);

                  // Optional: Add a retrieve check immediately after store
                  KeyPair retrieved = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
                  assertEquals(
                      kp.getPublic(),
                      retrieved.getPublic(),
                      "Public key mismatch in thread " + index);
                  assertEquals(
                      kp.getPrivate(),
                      retrieved.getPrivate(),
                      "Private key mismatch in thread " + index);

                } catch (DataHandlingException | AssertionError e) {
                  failures[index] = true;
                  System.err.println("Error in thread " + index + ": " + e.getMessage());
                  // Avoid printStackTrace in tests unless debugging, use fail() or log instead
                }
              });
    }

    for (Thread t : threads) {
      t.start();
    }

    for (Thread t : threads) {
      t.join();
    }

    for (int i = 0; i < numThreads; i++) {
      assertFalse(failures[i], "Thread " + i + " encountered an error.");
      // Verify final state after all threads complete
      try {
        String alias = "concurrentAlias_" + i;
        KeyPair expectedKeyPair = threadKeyPairs[i];
        KeyPair finalKeyPair = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
        assertEquals(
            expectedKeyPair.getPublic(),
            finalKeyPair.getPublic(),
            "Final public key check failed for alias " + alias);
        assertEquals(
            expectedKeyPair.getPrivate(),
            finalKeyPair.getPrivate(),
            "Final private key check failed for alias " + alias);
      } catch (DataHandlingException e) {
        fail("Failed to retrieve key pair stored by thread " + i + ": " + e.getMessage());
      }
    }
  }

  // =========================================================================
  // Tests for Constructor with String passwordSource (Environment Variable)
  // =========================================================================

  @Test
  void testConstructorWithValidEnvPasswordSource() throws DataHandlingException {
    String envPassword = System.getenv(TEST_PASSWORD_ENV_VAR);
    assumeTrue(
        envPassword != null && !envPassword.isEmpty(),
        TEST_PASSWORD_ENV_VAR + " environment variable must be set for this test.");

    Path envKeystorePath = tempDir.resolve("env_keystore_valid.p12");
    PKCS12KeyStorageHandler envHandler =
        PKCS12KeyStorageHandler.createFromEnvPassword(
            envKeystorePath.toString(), PASSWORD_SOURCE_VALID);

    assertNotNull(
        envHandler, "Handler should be created successfully with valid env var password source.");
    // We can optionally try a simple operation to ensure the password was likely correct
    assertDoesNotThrow(
        () -> envHandler.storeKeyPair("envTest", testKeyPair, testCertificate, KEY_ENTRY_PASSWORD),
        "Storing a key should succeed with handler initialized via env var.");
    assertTrue(
        Files.exists(envKeystorePath),
        "Keystore file should be created by handler initialized via env var.");
  }

  @Test
  void testConstructorWithUnsetEnvPasswordSource() {
    // Ensure the variable is unset for this test's scope (cannot be done reliably in-process)
    // We rely on the assumption that a unique, unset variable name is used.
    String unsetEnvVar = "THIS_ENV_VAR_SHOULD_REALLY_NOT_BE_SET_EVER";
    assumeTrue(
        System.getenv(unsetEnvVar) == null,
        unsetEnvVar + " environment variable must NOT be set for this test.");

    String passwordSourceUnset = "env:" + unsetEnvVar;
    Path envKeystorePath = tempDir.resolve("env_keystore_unset.p12");

    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              PKCS12KeyStorageHandler.createFromEnvPassword(
                  envKeystorePath.toString(), passwordSourceUnset);
            },
            "Constructor should fail if environment variable is not set.");

    assertTrue(
        exception.getMessage().contains("not set or empty"),
        "Exception message should indicate the environment variable was not set or empty.");
  }

  @Test
  void testConstructorWithEmptyEnvPasswordSource() {
    String envPasswordEmpty = System.getenv(TEST_PASSWORD_ENV_EMPTY_VAR);
    assumeTrue(
        envPasswordEmpty != null && envPasswordEmpty.isEmpty(),
        TEST_PASSWORD_ENV_EMPTY_VAR
            + " environment variable must be set to an empty string for this test.");

    Path envKeystorePath = tempDir.resolve("env_keystore_empty.p12");

    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              PKCS12KeyStorageHandler.createFromEnvPassword(
                  envKeystorePath.toString(), PASSWORD_SOURCE_EMPTY);
            },
            "Constructor should fail if environment variable is empty.");

    assertTrue(
        exception.getMessage().contains("not set or empty"),
        "Exception message should indicate the environment variable was not set or empty.");
  }

  @Test
  void testConstructorWithInvalidPasswordSourceFormat() {
    String invalidSource = "file:/path/to/password"; // Example of an unsupported format
    Path envKeystorePath = tempDir.resolve("env_keystore_invalid_format.p12");

    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              PKCS12KeyStorageHandler.createFromEnvPassword(
                  envKeystorePath.toString(), invalidSource);
            },
            "Constructor should fail with unsupported password source format.");

    assertTrue(
        exception.getMessage().contains("Unsupported password source format"),
        "Exception message should indicate unsupported format. Message: " + exception.getMessage());
  }

  // Test loading failure when using the env var constructor but providing the wrong password via
  // env var
  @Test
  void testLoadKeystoreWithIncorrectEnvPassword() throws DataHandlingException {
    String correctEnvPassword = System.getenv(TEST_PASSWORD_ENV_VAR);
    String wrongEnvPassword = System.getenv(TEST_PASSWORD_ENV_WRONG_VAR);
    assumeTrue(
        correctEnvPassword != null && !correctEnvPassword.isEmpty(),
        TEST_PASSWORD_ENV_VAR + " environment variable must be set for this test.");
    assumeTrue(
        wrongEnvPassword != null && !wrongEnvPassword.isEmpty(),
        TEST_PASSWORD_ENV_WRONG_VAR + " environment variable must be set for this test.");
    assumeTrue(
        !correctEnvPassword.equals(wrongEnvPassword),
        TEST_PASSWORD_ENV_VAR
            + " and "
            + TEST_PASSWORD_ENV_WRONG_VAR
            + " must have different values.");

    Path envKeystorePath = tempDir.resolve("env_keystore_wrong_pass.p12");
    String alias = "envAliasWrongPass";

    // 1. Create and store using the CORRECT password via env var
    PKCS12KeyStorageHandler correctHandler =
        PKCS12KeyStorageHandler.createFromEnvPassword(
            envKeystorePath.toString(), PASSWORD_SOURCE_VALID);
    correctHandler.storeKeyPair(alias, testKeyPair, testCertificate, KEY_ENTRY_PASSWORD);

    // 2. Attempt to create handler and load using the WRONG password via env var
    PKCS12KeyStorageHandler wrongHandler =
        PKCS12KeyStorageHandler.createFromEnvPassword(
            envKeystorePath.toString(), PASSWORD_SOURCE_WRONG);

    // 3. Attempting an operation that loads the keystore should fail
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              wrongHandler.getPublicKey(alias); // getPublicKey triggers loadKeyStore
            },
            "Loading keystore should fail with incorrect password from env var.");

    assertTrue(
        exception.getMessage().contains("Incorrect password")
            || (exception.getCause() != null
                && exception.getCause().getMessage().contains("mac check failed")),
        "Exception message should indicate incorrect keystore password or MAC failure. Message: "
            + exception.getMessage());
  }

  @Test
  void testConstructorWithEnvPasswordAndNullParentDir() throws DataHandlingException {
    String envPassword = System.getenv(TEST_PASSWORD_ENV_VAR);
    assumeTrue(
        envPassword != null && !envPassword.isEmpty(),
        TEST_PASSWORD_ENV_VAR + " environment variable must be set for this test.");

    String keystoreFileNameOnly = "env_keystore_no_dir.p12";
    Path keystoreInTempDir = tempDir.resolve(keystoreFileNameOnly); // Use tempDir for cleanup

    // Ensure file doesn't exist
    try {
      Files.deleteIfExists(keystoreInTempDir);
    } catch (IOException e) {
      fail("Failed to delete test keystore before test: " + e.getMessage());
    }

    // Initialize handler with just filename and valid env var source
    // This should succeed as the parent dir (tempDir) exists.
    PKCS12KeyStorageHandler envHandler =
        assertDoesNotThrow(
            () ->
                PKCS12KeyStorageHandler.createFromEnvPassword(
                    keystoreInTempDir.toString(), PASSWORD_SOURCE_VALID),
            "Constructor should succeed when parent directory is implicitly the current/temp"
                + " directory.");

    assertNotNull(envHandler, "Handler should be created successfully.");

    // Optional: Verify it works by storing something
    assertDoesNotThrow(
        () ->
            envHandler.storeKeyPair(
                "envTestNoDir", testKeyPair, testCertificate, KEY_ENTRY_PASSWORD),
        "Storing a key should succeed with handler initialized via env var and no explicit parent"
            + " dir.");
    assertTrue(Files.exists(keystoreInTempDir), "Keystore file should be created.");
  }

  // =========================================================================
  // Tests for Specific Error Conditions in retrieve/get
  // =========================================================================

  @Test
  void testRetrieveKeyPairForNonKeyEntryAlias() throws Exception {
    String trustedCertAlias = "trustedCert";
    // Manually create a keystore and add a trusted certificate entry
    KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
    ks.load(null, KEYSTORE_PASSWORD); // Initialize empty keystore
    ks.setCertificateEntry(trustedCertAlias, testCertificate); // Add cert only

    // Save this manually created keystore
    try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
      ks.store(fos, KEYSTORE_PASSWORD);
    }

    // Now use the handler (which will load this keystore)
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handler.retrieveKeyPair(
                  trustedCertAlias, KEY_ENTRY_PASSWORD); // Try to retrieve as KeyPair
            },
            "Retrieving a non-key entry as KeyPair should fail.");

    assertTrue(
        exception.getMessage().contains("is not a key entry"),
        "Exception message should indicate the alias is not a key entry. Message: "
            + exception.getMessage());
  }

  // Test specifically for ClassCastException possibility in retrieveKeyPair
  // This requires an entry that exists and is a Key but not a PrivateKey,
  // which is hard to create naturally with standard KeyStore APIs for PKCS12.
  // KeyStore.SecretKeyEntry might trigger this if we could store it and retrieve
  // via getKey, but PKCS12 typically focuses on private keys and certificates.
  // This test might remain theoretical unless a specific scenario is found.
  // @Test
  // void testRetrieveKeyPairClassCastException() throws Exception {
  //     String secretKeyAlias = "secretKeyAlias";
  //     // Setup: Manually create a keystore with a SecretKeyEntry if possible
  //     // KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
  //     // ks.load(null, KEYSTORE_PASSWORD);
  //     // SecretKey secretKey = ... // Generate or load a SecretKey
  //     // KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
  //     // ks.setEntry(secretKeyAlias, skEntry, new
  // KeyStore.PasswordProtection(KEY_ENTRY_PASSWORD));
  //     // try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
  //     //     ks.store(fos, KEYSTORE_PASSWORD);
  //     // }
  //
  //     // DataHandlingException wrapperEx = assertThrows(DataHandlingException.class, () -> {
  //     //     handler.retrieveKeyPair(secretKeyAlias, KEY_ENTRY_PASSWORD);
  //     // }, "Retrieving a non-PrivateKey entry should cause an issue.");
  //
  //     // assertTrue(wrapperEx.getMessage().contains("was not of the expected type (PrivateKey)"),
  //     //            "Exception message should indicate ClassCastException. Message: " +
  // wrapperEx.getMessage());
  //     // assertNotNull(wrapperEx.getCause());
  //     // assertTrue(wrapperEx.getCause() instanceof ClassCastException, "Cause should be
  // ClassCastException");
  // }

  @Test
  void testGetPublicKeyForNonKeyPairAlias() throws Exception {
    String trustedCertAlias = "trustedCertOnly";
    // Manually create a keystore and add a trusted certificate entry
    KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
    ks.load(null, KEYSTORE_PASSWORD); // Initialize empty keystore
    ks.setCertificateEntry(trustedCertAlias, testCertificate); // Add cert only

    // Save this manually created keystore
    try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
      ks.store(fos, KEYSTORE_PASSWORD);
    }

    // Use the handler to get the public key - this SHOULD work for a trusted cert entry
    PublicKey pubKey =
        assertDoesNotThrow(
            () -> handler.getPublicKey(trustedCertAlias),
            "Getting public key for a trusted certificate entry should succeed.");
    assertNotNull(pubKey);
    assertEquals(
        testCertificate.getPublicKey(), pubKey, "Public key from trusted cert entry should match.");
  }

  // Note: Testing the case where getCertificate returns null within getPublicKey is hard
  // because KeyStore.getCertificate usually returns null only if the alias doesn't exist,
  // which is already covered by testRetrieveNonExistentAlias. If an alias exists but
  // somehow has no certificate (which shouldn't happen with standard KeyStore operations),
  // mocking would be required.

  @Test
  void testLoadInvalidKeystoreFile() throws IOException {
    // Create an invalid file at the keystore path
    Files.writeString(keystorePath, "This is not a valid keystore file content.");

    // Handler initialization itself doesn't load, the first operation does.
    // Use the existing handler configured in setUp which points to keystorePath

    // Attempt an operation that triggers loading the keystore
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              handler.getPublicKey("anyAlias"); // Or retrieveKeyPair
            },
            "Loading an invalid keystore file should throw DataHandlingException.");

    // Check that the exception is a general load failure, not a password error
    assertTrue(
        exception.getMessage().contains("Failed to load or initialize keystore"),
        "Exception message should indicate a general load failure. Message: "
            + exception.getMessage());
    assertFalse(
        exception.getMessage().contains("Incorrect password"),
        "Exception message should not indicate an incorrect password for an invalid file. Message: "
            + exception.getMessage());
  }

  @Test
  void testConstructorDirectoryCreationFailure() throws IOException {
    Path parentDirAsFile = tempDir.resolve("parentDirFile");
    Path keystoreInFakeDir = parentDirAsFile.resolve("keystore.p12");

    // Create a file where the parent directory should be
    Files.createFile(parentDirAsFile);
    assertTrue(
        Files.exists(parentDirAsFile) && !Files.isDirectory(parentDirAsFile),
        "Parent directory path should exist as a file.");

    // Attempt to initialize the handler - should fail during directory creation
    DataHandlingException exception =
        assertThrows(
            DataHandlingException.class,
            () -> {
              PKCS12KeyStorageHandler.createWithPassword(
                  keystoreInFakeDir.toString(), KEYSTORE_PASSWORD);
            },
            "Constructor should fail if parent directory cannot be created.");

    assertTrue(
        exception.getMessage().contains("Invalid keystore path or permissions issue"),
        "Exception message should indicate path or permission issue. Message: "
            + exception.getMessage());
    // Check that the cause is likely an IOException (e.g., FileAlreadyExistsException or similar)
    assertNotNull(exception.getCause(), "Exception should have a cause.");
    assertTrue(exception.getCause() instanceof IOException, "Cause should be an IOException.");

    // Clean up the created file
    Files.deleteIfExists(parentDirAsFile);
  }
}
