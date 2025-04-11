package com.voteomatic.cryptography.io;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider; // Added for BC provider registration

import static org.junit.jupiter.api.Assertions.*;

// Requires setting an environment variable for the password.
// We can use a library like System Rules or Testcontainers for better env var management in tests,
// but for simplicity, we'll assume manual setup or skip if not set.
// Example: export TEST_KEYSTORE_PASSWORD='testpassword'
// Example: export TEST_KEYSTORE_WRONG_PASSWORD='wrongpassword'
// @DisabledIfEnvironmentVariable(named = "TEST_KEYSTORE_PASSWORD", matches = ".*", disabledReason = "TEST_KEYSTORE_PASSWORD environment variable not set")
// @DisabledIfEnvironmentVariable(named = "TEST_KEYSTORE_WRONG_PASSWORD", matches = ".*", disabledReason = "TEST_KEYSTORE_WRONG_PASSWORD environment variable not set for incorrect password test")
// Temporarily disable env var check for easier local testing if needed, re-enable for CI.
class PKCS12KeyStorageHandlerTest {

    // Static initializer to register BouncyCastle provider
    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    // Use fixed passwords for tests for simplicity, avoiding env var dependency during refactoring
    private static final char[] KEYSTORE_PASSWORD = "testpassword".toCharArray();
    private static final char[] WRONG_KEYSTORE_PASSWORD = "wrongpassword".toCharArray();
    private static final char[] KEY_ENTRY_PASSWORD = "keypassword".toCharArray(); // Password for the key entry itself

    // Re-enable env var usage if required:
    // private static final String TEST_PASSWORD_ENV_VAR = "TEST_KEYSTORE_PASSWORD";
    // private static final String TEST_WRONG_PASSWORD_ENV_VAR = "TEST_KEYSTORE_WRONG_PASSWORD";
    // private static final String PASSWORD_SOURCE = "env:" + TEST_PASSWORD_ENV_VAR;
    // private static final String WRONG_PASSWORD_SOURCE = "env:" + TEST_WRONG_PASSWORD_ENV_VAR;

    private static KeyPair testKeyPair;
    private static X509Certificate testCertificate;

    @TempDir
    Path tempDir;

    private Path keystorePath;
    private PKCS12KeyStorageHandler handler;

    // Generate KeyPair and Certificate once for all tests
    @BeforeAll
    static void generateTestData() throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
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
        handler = new PKCS12KeyStorageHandler(keystorePath.toString(), KEYSTORE_PASSWORD);
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
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                owner,              // Issuer DN (same as subject for self-signed)
                serialNumber,       // Serial number
                validityBeginDate,  // Not before
                validityEndDate,    // Not after
                owner,              // Subject DN
                publicKey);         // Public key

        // Sign the certificate using the private key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA") // Use appropriate algorithm
                                    .setProvider("BC") // Specify BouncyCastle provider
                                    .build(privateKey);

        // Build and return the certificate
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
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
        assertEquals(testKeyPair.getPublic(), retrievedKeyPair.getPublic(), "Retrieved public key should match original.");
        assertEquals(testKeyPair.getPrivate(), retrievedKeyPair.getPrivate(), "Retrieved private key should match original.");

        // Also test getPublicKey
        PublicKey retrievedPublicKey = handler.getPublicKey(alias);
        assertNotNull(retrievedPublicKey, "Retrieved public key (via getPublicKey) should not be null.");
        assertEquals(testKeyPair.getPublic(), retrievedPublicKey, "Retrieved public key (via getPublicKey) should match original.");
    }

    @Test
    void testRetrieveNonExistentAlias() {
        String alias = "nonExistentAlias";

        // Attempt to retrieve non-existent alias
        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
        }, "Retrieving non-existent alias should throw DataHandlingException.");

        assertTrue(exception.getMessage().contains("Alias not found"), "Exception message should indicate alias not found.");

        // Also test getPublicKey for non-existent alias
         DataHandlingException pubKeyException = assertThrows(DataHandlingException.class, () -> {
             handler.getPublicKey(alias);
         }, "Getting public key for non-existent alias should throw DataHandlingException.");

         assertTrue(pubKeyException.getMessage().contains("Alias not found"), "Public key exception message should indicate alias not found.");
    }

    @Test
    void testOverwriteExistingKeyPair() throws DataHandlingException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
        String alias = "overwriteAlias";
        KeyPair initialKeyPair = testKeyPair; // Use the globally generated one
        Certificate initialCertificate = testCertificate;

        // Generate a new keypair and certificate for overwriting
        KeyPair updatedKeyPair = generateTestingKeyPair();
        Certificate updatedCertificate = generateSelfSignedCertificate(updatedKeyPair, "CN=Updated Test Cert");

        // Store initial key pair
        handler.storeKeyPair(alias, initialKeyPair, initialCertificate, KEY_ENTRY_PASSWORD);
        KeyPair retrievedInitial = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
        assertEquals(initialKeyPair.getPublic(), retrievedInitial.getPublic(), "Initial retrieved public key should match.");
        assertEquals(initialKeyPair.getPrivate(), retrievedInitial.getPrivate(), "Initial retrieved private key should match.");

        // Store updated key pair (overwrite)
        handler.storeKeyPair(alias, updatedKeyPair, updatedCertificate, KEY_ENTRY_PASSWORD);
        KeyPair retrievedUpdated = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
        assertEquals(updatedKeyPair.getPublic(), retrievedUpdated.getPublic(), "Updated retrieved public key should match.");
        assertEquals(updatedKeyPair.getPrivate(), retrievedUpdated.getPrivate(), "Updated retrieved private key should match.");
        assertNotEquals(initialKeyPair.getPublic(), retrievedUpdated.getPublic(), "Updated public key should differ from initial.");
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

        assertFalse(Files.exists(deepPath.getParent()), "Parent directory should not exist before initialization.");

        // Initialize handler with a path requiring directory creation
        new PKCS12KeyStorageHandler(deepPath.toString(), KEYSTORE_PASSWORD);

        assertTrue(Files.exists(deepPath.getParent()), "Parent directory should be created during initialization.");
    }

    // This test verifies that loading the *keystore* with the wrong password fails.
    @Test
    void testLoadKeystoreWithIncorrectPassword() throws DataHandlingException {
         String alias = "testAlias";
         // Store something first using the correct keystore password
         handler.storeKeyPair(alias, testKeyPair, testCertificate, KEY_ENTRY_PASSWORD);

         // Create a handler instance using the incorrect keystore password
         PKCS12KeyStorageHandler handlerWithWrongPassword = new PKCS12KeyStorageHandler(keystorePath.toString(), WRONG_KEYSTORE_PASSWORD);

         // Attempt to retrieve (which triggers loading the keystore) should fail
         DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
             handlerWithWrongPassword.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD); // Password here is for the key entry, but load fails first
         }, "Retrieving with incorrect keystore password should throw DataHandlingException during load.");

         // The exception message comes from loadKeyStore()
         assertTrue(exception.getMessage().contains("Incorrect password") || (exception.getCause() != null && exception.getCause().getMessage().contains("mac check failed")),
                    "Exception message should indicate incorrect keystore password or MAC failure during load. Message: " + exception.getMessage());
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
         DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
             handler.retrieveKeyPair(alias, wrongEntryPassword);
         }, "Retrieving with incorrect key entry password should throw DataHandlingException.");

         // The exception message comes from retrieveKeyPair() -> keyStore.getKey()
         assertTrue(exception.getMessage().contains("Incorrect password provided"), // Check specific message from retrieveKeyPair
                    "Exception message should indicate incorrect key entry password. Message: " + exception.getMessage());
    }

    @Test
    void testStoreMultipleKeyPairs() throws DataHandlingException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
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
        for(int i=0; i<numThreads; i++) {
            try {
                threadKeyPairs[i] = generateTestingKeyPair();
                threadCertificates[i] = generateSelfSignedCertificate(threadKeyPairs[i], "CN=Concurrent " + i);
            } catch (Exception e) {
                 fail("Failed to generate test data for concurrency test: " + e.getMessage());
            }
        }


        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            final KeyPair kp = threadKeyPairs[index];
            final Certificate cert = threadCertificates[index];
            threads[i] = new Thread(() -> {
                try {
                    String alias = "concurrentAlias_" + index;
                    // Use a unique password per entry if needed, or reuse KEY_ENTRY_PASSWORD
                    handler.storeKeyPair(alias, kp, cert, KEY_ENTRY_PASSWORD);

                    // Optional: Add a retrieve check immediately after store
                    KeyPair retrieved = handler.retrieveKeyPair(alias, KEY_ENTRY_PASSWORD);
                    assertEquals(kp.getPublic(), retrieved.getPublic(), "Public key mismatch in thread " + index);
                    assertEquals(kp.getPrivate(), retrieved.getPrivate(), "Private key mismatch in thread " + index);

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
                 assertEquals(expectedKeyPair.getPublic(), finalKeyPair.getPublic(), "Final public key check failed for alias " + alias);
                 assertEquals(expectedKeyPair.getPrivate(), finalKeyPair.getPrivate(), "Final private key check failed for alias " + alias);
            } catch (DataHandlingException e) {
                 fail("Failed to retrieve key pair stored by thread " + i + ": " + e.getMessage());
            }
        }
    }
    // Note: Removed testInitializationCreatesDirectory as the constructor now handles this,
    // and testing constructor side effects directly can be brittle.
    // The setUp() method implicitly relies on this directory creation.
}