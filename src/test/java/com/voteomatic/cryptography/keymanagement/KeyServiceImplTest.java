package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.io.DataHandlingException;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.io.PKCS12KeyStorageHandler; // Import the real handler
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir; // Import TempDir

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
// No longer need Mockito imports

// No longer need Mockito extension
class KeyServiceImplTest {

    private KeyService keyService;
    private SecureRandomGenerator secureRandomGenerator;
    private static final BigInteger P = new BigInteger("23"); // Small prime for faster tests
    private static final BigInteger G = new BigInteger("5");  // Generator for P=23
    private static final String PUBLIC_KEY_SUFFIX = "_public";
    private static final String PRIVATE_KEY_SUFFIX = "_private";
    private static final char[] TEST_PASSWORD = "testpassword".toCharArray();

    @TempDir
    Path tempDir; // JUnit manages this temporary directory

    private KeyStorageHandler keyStorageHandler; // Use the real handler
    private Path keyStorePath;

    @BeforeEach // setUp configures mocks that throw checked exceptions
    void setUp() throws DataHandlingException {
        secureRandomGenerator = new SecureRandomGeneratorImpl();
        keyStorePath = tempDir.resolve("test_keystore.p12");

        // Initialize the real PKCS12 handler
        keyStorageHandler = new PKCS12KeyStorageHandler(keyStorePath.toString(), TEST_PASSWORD);

        // Use the real handler instance
        keyService = new KeyServiceImpl(P, G, keyStorageHandler, secureRandomGenerator);
    }

    @AfterEach
    void tearDown() throws IOException {
        // Clean up the keystore file after each test for isolation
        Files.deleteIfExists(keyStorePath);
    }

    @Test
    void testGenerateKeyPair_Success() throws KeyManagementException {
        KeyPair keyPair = keyService.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());
        
        PublicKey publicKey = keyPair.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivateKey();
        
        assertEquals(P, publicKey.getP());
        assertEquals(G, publicKey.getG());
        assertEquals(P, privateKey.getP());
        assertEquals(G, privateKey.getG());
    }

    @Test
    void testStoreAndRetrieveKeyPair_Success() throws KeyManagementException {
        KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-key";
        // Use the real handler: writeData stores in the temp file
        keyService.storeKeyPair(keyPair, identifier);
        // Use the real handler: readData retrieves from the temp file
        KeyPair retrieved = keyService.retrieveKeyPair(identifier);
        assertEquals(keyPair, retrieved);
        // No mock verification needed
    }

    @Test
    void testRetrieveKeyPair_NotFound() {
        // The real handler will throw DataHandlingException, wrapped by KeyServiceImpl
        assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair("nonexistent"));
        // No mock verification needed
    }

    @Test
    void testConcurrentOperations() throws InterruptedException {
        final int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        // No mock configuration needed, the real handler has internal synchronization

        for (int i = 0; i < threadCount; i++) {
            final String id = "concurrent-" + i;
            executor.submit(() -> {
                try {
                    KeyPair keyPair = keyService.generateKeyPair();
                    keyService.storeKeyPair(keyPair, id); // Uses real handler (writes to file)
                    KeyPair retrieved = keyService.retrieveKeyPair(id); // Uses real handler (reads from file)
                    assertEquals(keyPair, retrieved);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    System.err.println("Concurrent operation failed for " + id + ": " + e.getMessage());
                    e.printStackTrace(); // Print stack trace for debugging
                    failureCount.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Latch timed out"); // Increased timeout
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "Executor shutdown timed out");

        assertEquals(0, failureCount.get(), "Some concurrent operations failed.");
        assertEquals(threadCount, successCount.get(), "Not all concurrent operations succeeded.");
    }

    @Test
    void testConstructor_NullP() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(null, G, keyStorageHandler, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullG() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, null, keyStorageHandler, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullStorageHandler() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, G, null, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullRandomGenerator() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, G, keyStorageHandler, null));
    }
    @Test
    void testGetPublicKey_Success() throws Exception { // Keep Exception for KeyPair generation, add DataHandlingException
        KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-public-key";
        keyService.storeKeyPair(keyPair, identifier); // Uses real handler

        // No mock needed
        PublicKey publicKey = keyService.getPublicKey(identifier);
        assertNotNull(publicKey);
        assertEquals(keyPair.getPublicKey(), publicKey);
        // No mock verification needed
    }

    @Test
    void testGetPublicKey_NotFound() {
        // Real handler throws DataHandlingException, wrapped by KeyServiceImpl
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey("nonexistent"));
        // No mock verification needed
    }

    @Test
    void testGetPublicKey_NullId() {
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(null));
    }

    @Test
    void testGetPublicKey_EmptyId() {
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(""));
    }

    @Test
    void testVerifyKeyIntegrity_ValidKey() {
        try {
            KeyPair keyPair = keyService.generateKeyPair();
            assertTrue(keyService.verifyKeyIntegrity(keyPair.getPublicKey()));
        } catch (KeyManagementException e) {
            fail("Key generation failed: " + e.getMessage());
        }
    }

    @Test
    void testVerifyKeyIntegrity_NullKey() {
        assertThrows(KeyManagementException.class, () ->
            keyService.verifyKeyIntegrity(null));
    }

    @Test
    void testVerifyKeyIntegrity_InvalidKey() {
        try {
            KeyPair keyPair = keyService.generateKeyPair();
            // Create a modified public key with invalid parameters
        PublicKey invalidKey = new PublicKey(
            keyPair.getPublicKey().getP().add(BigInteger.ONE), // Modified p
            keyPair.getPublicKey().getG(),
            keyPair.getPublicKey().getY()
        );
            assertFalse(keyService.verifyKeyIntegrity(invalidKey));
        } catch (KeyManagementException e) {
            fail("Key generation failed: " + e.getMessage());
        }
    }

    @Test
    void testStoreKeyPair_NullKeyPair() {
        assertThrows(KeyManagementException.class, () ->
            keyService.storeKeyPair(null, "test-id"));
    }

    @Test
    void testStoreKeyPair_NullId() throws KeyManagementException {
        KeyPair keyPair = keyService.generateKeyPair();
        assertThrows(KeyManagementException.class, () ->
            keyService.storeKeyPair(keyPair, null));
    }

    @Test
    void testStoreKeyPair_EmptyId() throws KeyManagementException {
        KeyPair keyPair = keyService.generateKeyPair();
        assertThrows(KeyManagementException.class, () ->
            keyService.storeKeyPair(keyPair, ""));
    }

    @Test
    void testStoreKeyPair_InvalidParameters() throws Exception {
        try {
            KeyPair keyPair = keyService.generateKeyPair();
            // Create a key pair with different parameters than the service instance
            KeyService differentService = new KeyServiceImpl(
                P.add(BigInteger.ONE), // Different p - Use a different P for this service
                G,
                keyStorageHandler, // Can reuse the same handler, but the service checks P/G
                secureRandomGenerator // Use the same generator
            );
            assertThrows(KeyManagementException.class, () ->
                differentService.storeKeyPair(keyPair, "test-id"));
        } catch (KeyManagementException e) {
            fail("Key generation failed: " + e.getMessage());
        }
    }

    @Test
    void testGenerateKeyPair_SmallP() {
        // Test with p=2 which should fail
        KeyService smallKeyService = new KeyServiceImpl(
            BigInteger.valueOf(2),
            G, // Use the same G
            keyStorageHandler, // Use the same handler
            secureRandomGenerator
        );
        assertThrows(KeyManagementException.class, () ->
            smallKeyService.generateKeyPair());
    }

    // --- Tests for retrieveKeyPair Error Handling ---

    // --- Tests for retrieveKeyPair Error Handling (Real Handler) ---

    // Note: Simulating specific I/O failures with the real handler is complex.
    // We rely on the "NotFound" test for the basic failure path.
    // Tests for deserialization errors within KeyServiceImpl remain relevant.

    // Test for reading private key when public key exists but private doesn't
    @Test
    void testRetrieveKeyPair_PrivateKeyNotFound() throws Exception {
        String keyId = "missing-priv";
        KeyPair keyPair = keyService.generateKeyPair();
        // Store only the public key using the handler directly (bypass service logic for test setup)
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, serializePublicKey(keyPair.getPublicKey()));

        // Attempting to retrieve the pair should fail because private key is missing
        assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(keyId));
    }

    // Test deserialization failure by writing corrupted data directly via handler
    @Test
    void testRetrieveKeyPair_PublicKeyDeserializationFails() throws Exception {
        String keyId = "fail-deserialize-pub";
        byte[] corruptedData = "corrupted".getBytes();
        // Write corrupted data directly using the handler
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, corruptedData);
        // Write dummy private key data so the second read doesn't fail immediately
        keyStorageHandler.writeData(keyId + PRIVATE_KEY_SUFFIX, "dummy".getBytes());

        // KeyServiceImpl should fail during deserialization
        assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(keyId));
    }

    // Test deserialization failure for private key
    @Test
    void testRetrieveKeyPair_PrivateKeyDeserializationFails() throws Exception {
        String keyId = "fail-deserialize-priv";
        KeyPair keyPair = keyService.generateKeyPair(); // Need valid public key data
        byte[] validPublicKeyBytes = serializePublicKey(keyPair.getPublicKey());
        byte[] corruptedData = "corrupted".getBytes();

        // Write valid public key and corrupted private key directly via handler
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, validPublicKeyBytes);
        keyStorageHandler.writeData(keyId + PRIVATE_KEY_SUFFIX, corruptedData);

        // KeyServiceImpl should fail during private key deserialization
        assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(keyId));
    }

    // Test mismatch in parameters (P, G) during deserialization
    @Test
    void testRetrieveKeyPair_MismatchedPublicKeyParams() throws Exception {
        String keyId = "mismatch-pub-params";
        // Create key data with P+1
        PublicKey wrongParamsPubKey = new PublicKey(P.add(BigInteger.ONE), G, BigInteger.TEN);
        PrivateKey matchingPrivKey = new PrivateKey(P.add(BigInteger.ONE), G, BigInteger.ONE); // Needs matching P/G for serialization
        byte[] wrongPublicKeyBytes = serializePublicKey(wrongParamsPubKey);
        byte[] matchingPrivateKeyBytes = serializePrivateKey(matchingPrivKey);

        // Write data directly using the handler
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, wrongPublicKeyBytes);
        keyStorageHandler.writeData(keyId + PRIVATE_KEY_SUFFIX, matchingPrivateKeyBytes);

        // KeyServiceImpl (using P, G) should detect mismatch during deserialization
        assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(keyId));
    }

   @Test
   void testRetrieveKeyPair_MismatchedPrivateKeyParams() throws Exception {
       String keyId = "mismatch-priv-params";
       KeyPair keyPair = keyService.generateKeyPair(); // Uses service's P, G
       // Create private key data with P+1
       PrivateKey wrongParamsPrivKey = new PrivateKey(P.add(BigInteger.ONE), G, BigInteger.ONE);
       byte[] validPublicKeyBytes = serializePublicKey(keyPair.getPublicKey());
       byte[] wrongPrivateKeyBytes = serializePrivateKey(wrongParamsPrivKey);

       // Write data directly using the handler
       keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, validPublicKeyBytes);
       keyStorageHandler.writeData(keyId + PRIVATE_KEY_SUFFIX, wrongPrivateKeyBytes);

       // KeyServiceImpl should detect mismatch during private key deserialization
       assertThrows(KeyManagementException.class, () ->
           keyService.retrieveKeyPair(keyId));
   }

    // --- Tests for getPublicKey Error Handling (Real Handler) ---

    // Note: Simulating I/O failures is hard. Rely on NotFound test.

    @Test
    void testGetPublicKey_DeserializationFails() throws Exception {
        String keyId = "fail-deserialize-pub-only";
        byte[] corruptedData = "corrupted".getBytes();
        // Write corrupted data directly using the handler
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, corruptedData);

        // KeyServiceImpl should fail during deserialization
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(keyId));
    }

    @Test
    void testGetPublicKey_MismatchedParams() throws Exception {
        String keyId = "mismatch-params-pub-only";
        // Create key data with P+1
        PublicKey wrongParamsKey = new PublicKey(P.add(BigInteger.ONE), G, BigInteger.TEN);
        byte[] wrongPublicKeyBytes = serializePublicKey(wrongParamsKey);

        // Write data directly using the handler
        keyStorageHandler.writeData(keyId + PUBLIC_KEY_SUFFIX, wrongPublicKeyBytes);

        // KeyServiceImpl should detect mismatch during deserialization
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(keyId));
    }

    // --- Tests for storeKeyPair Error Handling (Real Handler) ---

    // Note: Simulating write failures (e.g., disk full, permissions) is difficult in unit tests.
    // We assume the handler works if the setup is correct.
    // The existing tests for null/empty ID and mismatched parameters remain valid.

    // --- Tests for verifyKeyIntegrity ---

    // Note: Tests for null P, G, Y in PublicKey removed,
    // as PublicKey constructor prevents this.

    @Test
    void testVerifyKeyIntegrity_MismatchedG() throws KeyManagementException {
        PublicKey key = new PublicKey(P, G.add(BigInteger.ONE), BigInteger.TEN);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YLessThanOne() throws KeyManagementException {
        PublicKey key = new PublicKey(P, G, BigInteger.ZERO);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YEqualsP() throws KeyManagementException {
        PublicKey key = new PublicKey(P, G, P);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YGreaterThanP() throws KeyManagementException {
        PublicKey key = new PublicKey(P, G, P.add(BigInteger.ONE));
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    // --- Helper methods needed for setting up corrupted/mismatched data tests ---
    // These are needed because we bypass KeyServiceImpl to write bad data via the handler directly.

    private byte[] serializePublicKey(PublicKey key) throws IOException {
        // This logic must match KeyServiceImpl's internal serialization
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(bos)) {
            serializeBigInteger(dos, key.getP());
            serializeBigInteger(dos, key.getG());
            serializeBigInteger(dos, key.getY());
            return bos.toByteArray();
        }
    }

     private byte[] serializePrivateKey(PrivateKey key) throws IOException {
        // This logic must match KeyServiceImpl's internal serialization
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(bos)) {
            serializeBigInteger(dos, key.getP());
            serializeBigInteger(dos, key.getG());
            serializeBigInteger(dos, key.getX());
            return bos.toByteArray();
        }
    }

    private void serializeBigInteger(DataOutputStream dos, BigInteger bi) throws IOException {
        // This logic must match KeyServiceImpl's internal serialization
        byte[] bytes = bi.toByteArray();
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }

    // No deserialize helpers needed in the test class itself anymore.
}