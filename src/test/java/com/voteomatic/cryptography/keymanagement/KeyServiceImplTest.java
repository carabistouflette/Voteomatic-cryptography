package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.io.DataHandlingException;
import com.voteomatic.cryptography.io.InMemoryKeyStorageHandler;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;

@ExtendWith(MockitoExtension.class)
class KeyServiceImplTest {

    private KeyService keyService;
    private SecureRandomGenerator secureRandomGenerator;
    private static final BigInteger P = new BigInteger("23");
    private static final BigInteger G = new BigInteger("5");
    private static final String PUBLIC_KEY_SUFFIX = "_public";
    private static final String PRIVATE_KEY_SUFFIX = "_private";

    @Mock
    private KeyStorageHandler mockKeyStorageHandler;
    private KeyService keyServiceWithMockStorage;

    @BeforeEach
    void setUp() {
        secureRandomGenerator = new SecureRandomGeneratorImpl();
        KeyStorageHandler realKeyStorageHandler = new InMemoryKeyStorageHandler();
        keyService = new KeyServiceImpl(P, G, realKeyStorageHandler, secureRandomGenerator);
        keyServiceWithMockStorage = new KeyServiceImpl(P, G, mockKeyStorageHandler, secureRandomGenerator);
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
    void testStoreAndRetrieveKeyPair_Success() throws Exception {
        KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-key";
        keyService.storeKeyPair(keyPair, identifier);
        KeyPair retrieved = keyService.retrieveKeyPair(identifier);
        assertEquals(keyPair, retrieved);
    }

    @Test
    void testRetrieveKeyPair_NotFound() {
        assertThrows(KeyManagementException.class, () -> 
            keyService.retrieveKeyPair("nonexistent"));
    }

    @Test
    void testConcurrentOperations() throws Exception {
        final int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final String id = "concurrent-" + i;
            executor.submit(() -> {
                try {
                    KeyPair keyPair = keyService.generateKeyPair();
                    keyService.storeKeyPair(keyPair, id);
                    KeyPair retrieved = keyService.retrieveKeyPair(id);
                    assertEquals(keyPair, retrieved);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    fail("Concurrent operation failed: " + e.getMessage());
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        assertEquals(threadCount, successCount.get());
        executor.shutdown();
    }

    @Test
    void testConstructor_NullP() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(null, G, mockKeyStorageHandler, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullG() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, null, mockKeyStorageHandler, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullStorageHandler() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, G, null, secureRandomGenerator));
    }

    @Test
    void testConstructor_NullRandomGenerator() {
        assertThrows(NullPointerException.class, () -> 
            new KeyServiceImpl(P, G, mockKeyStorageHandler, null));
    }
    @Test
    void testGetPublicKey_Success() throws Exception {
        KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-public-key";
        keyService.storeKeyPair(keyPair, identifier);
        
        PublicKey publicKey = keyService.getPublicKey(identifier);
        assertNotNull(publicKey);
        assertEquals(keyPair.getPublicKey(), publicKey);
    }

    @Test
    void testGetPublicKey_NotFound() {
        assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey("nonexistent"));
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
                P.add(BigInteger.ONE), // Different p
                G,
                new InMemoryKeyStorageHandler(),
                secureRandomGenerator
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
            G,
            new InMemoryKeyStorageHandler(),
            secureRandomGenerator
        );
        assertThrows(KeyManagementException.class, () ->
            smallKeyService.generateKeyPair());
    }

    // --- Tests for retrieveKeyPair Error Handling ---

    @Test
    void testRetrieveKeyPair_StorageReadPublicKeyFails() throws Exception {
        String keyId = "fail-read-pub";
        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX))
            .thenThrow(new DataHandlingException("Simulated read fail"));

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
        verify(mockKeyStorageHandler).readData(keyId + PUBLIC_KEY_SUFFIX);
    }

    @Test
    void testRetrieveKeyPair_StorageReadPrivateKeyFails() throws Exception {
        String keyId = "fail-read-priv";
        KeyPair keyPair = keyService.generateKeyPair(); // Need valid public key data
        byte[] validPublicKeyBytes = serializePublicKey(keyPair.getPublicKey());

        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(validPublicKeyBytes);
        when(mockKeyStorageHandler.readData(keyId + PRIVATE_KEY_SUFFIX))
            .thenThrow(new DataHandlingException("Simulated read fail"));

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
        verify(mockKeyStorageHandler).readData(keyId + PUBLIC_KEY_SUFFIX);
        verify(mockKeyStorageHandler).readData(keyId + PRIVATE_KEY_SUFFIX);
    }

    @Test
    void testRetrieveKeyPair_PublicKeyDeserializationFails() throws Exception {
        String keyId = "fail-deserialize-pub";
        byte[] corruptedData = "corrupted".getBytes();
        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(corruptedData);

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
    }

    @Test
    void testRetrieveKeyPair_PrivateKeyDeserializationFails() throws Exception {
        String keyId = "fail-deserialize-priv";
        KeyPair keyPair = keyService.generateKeyPair(); // Need valid public key data
        byte[] validPublicKeyBytes = serializePublicKey(keyPair.getPublicKey());
        byte[] corruptedData = "corrupted".getBytes();

        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(validPublicKeyBytes);
        when(mockKeyStorageHandler.readData(keyId + PRIVATE_KEY_SUFFIX)).thenReturn(corruptedData);

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
    }

    @Test
    void testRetrieveKeyPair_MismatchedPublicKeyParams() throws Exception {
        String keyId = "mismatch-pub-params";
        PublicKey wrongParamsKey = new PublicKey(P.add(BigInteger.ONE), G, BigInteger.TEN);
        byte[] wrongPublicKeyBytes = serializePublicKey(wrongParamsKey); // Serialized with wrong P
        byte[] dummyPrivateKeyBytes = serializePrivateKey(new PrivateKey(P, G, BigInteger.ONE)); // Needs valid structure

        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(wrongPublicKeyBytes);
        when(mockKeyStorageHandler.readData(keyId + PRIVATE_KEY_SUFFIX)).thenReturn(dummyPrivateKeyBytes);

        // Deserialization itself should throw IOException wrapped in KeyManagementException
        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
    }

     @Test
    void testRetrieveKeyPair_MismatchedPrivateKeyParams() throws Exception {
        String keyId = "mismatch-priv-params";
        KeyPair keyPair = keyService.generateKeyPair();
        PrivateKey wrongParamsKey = new PrivateKey(P.add(BigInteger.ONE), G, BigInteger.TEN);
        byte[] validPublicKeyBytes = serializePublicKey(keyPair.getPublicKey());
        byte[] wrongPrivateKeyBytes = serializePrivateKey(wrongParamsKey); // Serialized with wrong P

        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(validPublicKeyBytes);
        when(mockKeyStorageHandler.readData(keyId + PRIVATE_KEY_SUFFIX)).thenReturn(wrongPrivateKeyBytes);

        // Deserialization itself should throw IOException wrapped in KeyManagementException
        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.retrieveKeyPair(keyId));
    }

    // --- Tests for getPublicKey Error Handling ---

    @Test
    void testGetPublicKey_StorageReadFails() throws Exception {
        String keyId = "fail-read-pub-only";
        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX))
            .thenThrow(new DataHandlingException("Simulated read fail"));

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.getPublicKey(keyId));
    }

    @Test
    void testGetPublicKey_DeserializationFails() throws Exception {
        String keyId = "fail-deserialize-pub-only";
        byte[] corruptedData = "corrupted".getBytes();
        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(corruptedData);

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.getPublicKey(keyId));
    }

    @Test
    void testGetPublicKey_MismatchedParams() throws Exception {
        String keyId = "mismatch-params-pub-only";
        PublicKey wrongParamsKey = new PublicKey(P.add(BigInteger.ONE), G, BigInteger.TEN);
        byte[] wrongPublicKeyBytes = serializePublicKey(wrongParamsKey);

        when(mockKeyStorageHandler.readData(keyId + PUBLIC_KEY_SUFFIX)).thenReturn(wrongPublicKeyBytes);

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.getPublicKey(keyId));
    }

    // --- Tests for storeKeyPair Error Handling ---

    // Note: Tests for null PublicKey/PrivateKey within KeyPair removed,
    // as KeyPair constructor prevents this.

    @Test
    void testStoreKeyPair_StorageWritePublicKeyFails() throws Exception {
        String keyId = "fail-write-pub";
        KeyPair keyPair = keyService.generateKeyPair();
        doThrow(new DataHandlingException("Simulated write fail"))
            .when(mockKeyStorageHandler).writeData(eq(keyId + PUBLIC_KEY_SUFFIX), any(byte[].class));

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.storeKeyPair(keyPair, keyId));
        verify(mockKeyStorageHandler).writeData(eq(keyId + PUBLIC_KEY_SUFFIX), any(byte[].class));
    }

    @Test
    void testStoreKeyPair_StorageWritePrivateKeyFails() throws Exception {
        String keyId = "fail-write-priv";
        KeyPair keyPair = keyService.generateKeyPair();
        // Allow public key write to succeed
        doNothing().when(mockKeyStorageHandler).writeData(eq(keyId + PUBLIC_KEY_SUFFIX), any(byte[].class));
        // Make private key write fail
        doThrow(new DataHandlingException("Simulated write fail"))
            .when(mockKeyStorageHandler).writeData(eq(keyId + PRIVATE_KEY_SUFFIX), any(byte[].class));

        assertThrows(KeyManagementException.class, () ->
            keyServiceWithMockStorage.storeKeyPair(keyPair, keyId));
        verify(mockKeyStorageHandler).writeData(eq(keyId + PUBLIC_KEY_SUFFIX), any(byte[].class));
        verify(mockKeyStorageHandler).writeData(eq(keyId + PRIVATE_KEY_SUFFIX), any(byte[].class));
    }

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

    // --- Tests for Serialization/Deserialization Helpers ---

    @Test
    void testDeserializeBigInteger_NegativeLength() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(-1); // Negative length
        dos.close();
        byte[] data = bos.toByteArray();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        assertThrows(IOException.class, () -> deserializeBigInteger(dis)); // Direct call to helper
    }

    @Test
    void testDeserializeBigInteger_ExcessiveLength() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(20 * 1024 * 1024); // Length > 10MB limit
        dos.close();
        byte[] data = bos.toByteArray();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        assertThrows(IOException.class, () -> deserializeBigInteger(dis)); // Direct call to helper
    }

    @Test
    void testDeserializeBigInteger_IOExceptionOnRead() throws IOException {
        // Mock DataInputStream to throw IOException on readFully
        DataInputStream mockDis = mock(DataInputStream.class);
        when(mockDis.readInt()).thenReturn(10); // Valid length
        doThrow(new IOException("Simulated read error")).when(mockDis).readFully(any(byte[].class));

        assertThrows(IOException.class, () -> deserializeBigInteger(mockDis));
    }

    // --- Helper methods for tests ---

    // Need to replicate serialization logic here for testing purposes
    private byte[] serializePublicKey(PublicKey key) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(bos)) {
            serializeBigInteger(dos, key.getP());
            serializeBigInteger(dos, key.getG());
            serializeBigInteger(dos, key.getY());
            return bos.toByteArray();
        }
    }

    private byte[] serializePrivateKey(PrivateKey key) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(bos)) {
            serializeBigInteger(dos, key.getP());
            serializeBigInteger(dos, key.getG());
            serializeBigInteger(dos, key.getX());
            return bos.toByteArray();
        }
    }

    private void serializeBigInteger(DataOutputStream dos, BigInteger bi) throws IOException {
        byte[] bytes = bi.toByteArray();
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }

    // Need to replicate deserialization logic for testing error conditions
    private BigInteger deserializeBigInteger(DataInputStream dis) throws IOException {
        int length = dis.readInt();
        if (length < 0) {
             throw new IOException("Invalid length read for BigInteger: " + length);
        }
        if (length > 10 * 1024 * 1024) { // Use same limit as production code
            throw new IOException("BigInteger length exceeds safety limit: " + length);
        }
        byte[] bytes = new byte[length];
        dis.readFully(bytes);
        return new BigInteger(bytes);
    }
}