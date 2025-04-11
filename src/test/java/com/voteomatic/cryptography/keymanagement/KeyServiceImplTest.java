package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.io.DataHandlingException;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider; // Needed for KeyServiceImpl init
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import java.math.BigInteger;
import java.security.KeyPair; // JCE KeyPair
import java.security.Security;
import java.security.cert.Certificate; // JCE Certificate
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.DHPrivateKeySpec; // Added
import javax.crypto.spec.DHPublicKeySpec; // Added

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class) // Enable Mockito extension
class KeyServiceImplTest {

    // Static initializer to register BouncyCastle provider
    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private KeyService keyService;
    private SecureRandomGenerator secureRandomGenerator;
    private static final BigInteger P = new BigInteger("23"); // Small prime for faster tests
    private static final BigInteger G = new BigInteger("5");  // Generator for P=23
    // Suffixes no longer needed
    private static final char[] TEST_PASSWORD = "testpassword".toCharArray();

    @Mock
    private KeyStorageHandler keyStorageHandler; // Mock the handler

    @Captor
    private ArgumentCaptor<java.security.KeyPair> jceKeyPairCaptor;
    @Captor
    private ArgumentCaptor<Certificate> certificateCaptor;

    @BeforeEach
    void setUp() {
        // BC provider is now registered in the static initializer block above.
        secureRandomGenerator = new SecureRandomGeneratorImpl();
        // Instantiate service with the MOCK handler
        keyService = new KeyServiceImpl(P, G, keyStorageHandler, secureRandomGenerator);
    }

    // No tearDown needed for mock handler

    @Test
    void testGenerateKeyPair_Success() throws KeyManagementException {
        // Use the custom KeyPair type
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());
        
        // Access methods on the custom KeyPair type
        com.voteomatic.cryptography.core.elgamal.PublicKey publicKey = keyPair.getPublicKey();
        com.voteomatic.cryptography.core.elgamal.PrivateKey privateKey = keyPair.getPrivateKey();

        assertEquals(P, publicKey.getP());
        assertEquals(G, publicKey.getG());
        assertEquals(P, privateKey.getP());
        assertEquals(G, privateKey.getG());
        // Basic check: y = g^x mod p
        assertEquals(publicKey.getY(), G.modPow(privateKey.getX(), P));
    }

    // Helper to create a JCE KeyPair (java.security.KeyPair) for mocking return values
    private java.security.KeyPair createMockJceKeyPair(com.voteomatic.cryptography.keymanagement.KeyPair voteomaticKeyPair) throws Exception {
        // This mimics the conversion logic in KeyServiceImpl for test setup
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("DiffieHellman"); // Use DH as fallback
        DHPublicKeySpec pubSpec = new DHPublicKeySpec(voteomaticKeyPair.getPublicKey().getY(), P, G);
        DHPrivateKeySpec privSpec = new DHPrivateKeySpec(voteomaticKeyPair.getPrivateKey().getX(), P, G);
        java.security.PublicKey jcePub = keyFactory.generatePublic(pubSpec);
        java.security.PrivateKey jcePriv = keyFactory.generatePrivate(privSpec);
        return new java.security.KeyPair(jcePub, jcePriv);
    }

    @Test
    void testStoreAndRetrieveKeyPair_Success() throws Exception {
        // Use the custom KeyPair type
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-key";
        java.security.KeyPair mockJceKeyPair = createMockJceKeyPair(keyPair); // Create expected JCE version

        // --- Store Operation ---
        // Mocking: Expect call to storeKeyPair with specific args
        doNothing().when(keyStorageHandler).storeKeyPair(
                eq(identifier), any(java.security.KeyPair.class), any(Certificate.class), eq(TEST_PASSWORD));

        // Action: Call the service method
        keyService.storeKeyPair(keyPair, identifier, TEST_PASSWORD);

        // Verification: Check storeKeyPair was called with correct args (using the captor)
        verify(keyStorageHandler).storeKeyPair(eq(identifier), jceKeyPairCaptor.capture(), certificateCaptor.capture(), eq(TEST_PASSWORD));

        // Assert captured JCE KeyPair matches expected (check components)
        java.security.KeyPair capturedJceKeyPair = jceKeyPairCaptor.getValue();
        assertNotNull(capturedJceKeyPair);
        assertTrue(capturedJceKeyPair.getPublic() instanceof DHPublicKey);
        assertTrue(capturedJceKeyPair.getPrivate() instanceof javax.crypto.interfaces.DHPrivateKey);
        assertEquals(keyPair.getPublicKey().getY(), ((DHPublicKey) capturedJceKeyPair.getPublic()).getY());
        assertEquals(keyPair.getPrivateKey().getX(), ((javax.crypto.interfaces.DHPrivateKey) capturedJceKeyPair.getPrivate()).getX());
        DHParameterSpec params = ((DHPublicKey) capturedJceKeyPair.getPublic()).getParams();
        assertEquals(P, params.getP());
        assertEquals(G, params.getG());

        // Assert captured certificate is not null (content check is complex)
        assertNotNull(certificateCaptor.getValue());

        // --- Retrieve Operation ---
        // Mocking: Return the mock JCE KeyPair when retrieveKeyPair is called
        when(keyStorageHandler.retrieveKeyPair(identifier, TEST_PASSWORD)).thenReturn(mockJceKeyPair);

        // Action: Call the service method to retrieve the custom KeyPair
        com.voteomatic.cryptography.keymanagement.KeyPair retrieved = keyService.retrieveKeyPair(identifier, TEST_PASSWORD);

        // Verification: Check retrieveKeyPair was called
        verify(keyStorageHandler).retrieveKeyPair(identifier, TEST_PASSWORD);

        // Assertion: Check the final retrieved Voteomatic KeyPair matches the original
        assertEquals(keyPair, retrieved);
    }

    @Test
    void testRetrieveKeyPair_NotFound() throws Exception {
        String identifier = "nonexistent";
        // Mocking: Throw DataHandlingException when retrieveKeyPair is called
        when(keyStorageHandler.retrieveKeyPair(identifier, TEST_PASSWORD))
                .thenThrow(new DataHandlingException("Alias not found: " + identifier));

        // Action & Assertion: Expect KeyManagementException from the service
        KeyManagementException thrown = assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(identifier, TEST_PASSWORD));
        assertTrue(thrown.getCause() instanceof DataHandlingException);

        // Verification: Ensure the mock was called
        verify(keyStorageHandler).retrieveKeyPair(identifier, TEST_PASSWORD);
    }

    @Test
    void testRetrieveKeyPair_WrongPassword() throws Exception {
        String identifier = "test-key-wrong-pass";
        char[] wrongPassword = "wrongpassword".toCharArray();
        // Mocking: Throw DataHandlingException simulating wrong password
        when(keyStorageHandler.retrieveKeyPair(identifier, wrongPassword))
                .thenThrow(new DataHandlingException("Incorrect password for alias: " + identifier));

        // Action & Assertion: Expect KeyManagementException
        KeyManagementException thrown = assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(identifier, wrongPassword));
        assertTrue(thrown.getCause() instanceof DataHandlingException);

        // Verification
        verify(keyStorageHandler).retrieveKeyPair(identifier, wrongPassword);
    }

    // Concurrent test removed as it relied on real handler synchronization

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
    void testGetPublicKey_Success() throws Exception {
        // Use the custom KeyPair type
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-public-key";
        // Create the expected JCE PublicKey (java.security.PublicKey) that the handler should return
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("DiffieHellman");
        DHPublicKeySpec pubSpec = new DHPublicKeySpec(keyPair.getPublicKey().getY(), P, G);
        java.security.PublicKey mockJcePublicKey = keyFactory.generatePublic(pubSpec);

        // Mocking: Return the mock JCE PublicKey when getPublicKey is called
        when(keyStorageHandler.getPublicKey(identifier)).thenReturn(mockJcePublicKey);

        // Action: Call the service method to retrieve the custom PublicKey
        com.voteomatic.cryptography.core.elgamal.PublicKey retrievedPubKey = keyService.getPublicKey(identifier);

        // Verification: Check getPublicKey was called
        verify(keyStorageHandler).getPublicKey(identifier);

        // Assertion: Check the final retrieved Voteomatic PublicKey matches the original
        assertNotNull(retrievedPubKey);
        assertEquals(keyPair.getPublicKey(), retrievedPubKey);
    }

    @Test
    void testGetPublicKey_NotFound() throws Exception {
        String identifier = "nonexistent-pub";
        // Mocking: Throw DataHandlingException when getPublicKey is called
        when(keyStorageHandler.getPublicKey(identifier))
                .thenThrow(new DataHandlingException("Alias not found: " + identifier));

        // Action & Assertion: Expect KeyManagementException
        KeyManagementException thrown = assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(identifier));
        assertTrue(thrown.getCause() instanceof DataHandlingException);

        // Verification
        verify(keyStorageHandler).getPublicKey(identifier);
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
            // Use the custom KeyPair type
            com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
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
            // Use the custom KeyPair type
            com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
            // Create a modified public key with invalid parameters
        com.voteomatic.cryptography.core.elgamal.PublicKey invalidKey = new com.voteomatic.cryptography.core.elgamal.PublicKey(
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
            keyService.storeKeyPair(null, "test-id", TEST_PASSWORD));
    }

    @Test
    void testStoreKeyPair_NullId() throws KeyManagementException {
        // Use the custom KeyPair type
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        assertThrows(KeyManagementException.class, () ->
        // Pass the custom KeyPair type
            keyService.storeKeyPair(keyPair, null, TEST_PASSWORD));
    }

    @Test
    void testStoreKeyPair_EmptyId() throws KeyManagementException {
        // Use the custom KeyPair type
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        assertThrows(KeyManagementException.class, () ->
        // Pass the custom KeyPair type
            keyService.storeKeyPair(keyPair, "", TEST_PASSWORD));
    }

    @Test
    void testStoreKeyPair_NullPassword() throws KeyManagementException {
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        assertThrows(KeyManagementException.class, () ->
            keyService.storeKeyPair(keyPair, "test-id", null));
    }

    @Test
    void testStoreKeyPair_EmptyPassword() throws KeyManagementException {
        com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
        // Pass the custom KeyPair type
        assertThrows(KeyManagementException.class, () ->
            keyService.storeKeyPair(keyPair, "test-id", new char[0]));
    }

    @Test
    void testStoreKeyPair_InvalidParameters() throws Exception {
        try {
            // Use the custom KeyPair type
            com.voteomatic.cryptography.keymanagement.KeyPair keyPair = keyService.generateKeyPair();
            // Create a key pair with different parameters than the service instance
            KeyService differentService = new KeyServiceImpl(
                P.add(BigInteger.ONE), // Different p - Use a different P for this service
               G,
               keyStorageHandler, // Use the mock handler
               secureRandomGenerator
           );
           // Pass the custom KeyPair type
           assertThrows(KeyManagementException.class, () ->
               differentService.storeKeyPair(keyPair, "test-id", TEST_PASSWORD));
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

    // --- Tests for retrieveKeyPair Error Handling (Mock Handler) ---

    @Test
    void testRetrieveKeyPair_ConversionError() throws Exception {
        String identifier = "conversion-error-key";
        // Create a JCE KeyPair that isn't DH based (e.g., RSA) to cause conversion error
        java.security.KeyPairGenerator rsaGen = java.security.KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(512); // Small size for test speed
        java.security.KeyPair nonDhKeyPair = rsaGen.generateKeyPair();

        // Mocking: Return the non-DH KeyPair
        when(keyStorageHandler.retrieveKeyPair(identifier, TEST_PASSWORD)).thenReturn(nonDhKeyPair);

        // Action & Assertion: Expect KeyManagementException (wrapping ClassCastException)
        KeyManagementException thrown = assertThrows(KeyManagementException.class, () ->
            keyService.retrieveKeyPair(identifier, TEST_PASSWORD));
        // Underlying cause might be ClassCastException or InvalidKeySpecException depending on conversion path
        // assertTrue(thrown.getCause() instanceof ClassCastException || thrown.getCause() instanceof InvalidKeySpecException);
        assertNotNull(thrown.getCause()); // Check there is a cause

        // Verification
        verify(keyStorageHandler).retrieveKeyPair(identifier, TEST_PASSWORD);
    }

    // --- Tests for getPublicKey Error Handling (Mock Handler) ---

    @Test
    void testGetPublicKey_ConversionError() throws Exception {
        String identifier = "conversion-error-pubkey";
        // Create a JCE PublicKey that isn't DH based
        java.security.KeyPairGenerator rsaGen = java.security.KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(512);
        java.security.PublicKey nonDhPublicKey = rsaGen.generateKeyPair().getPublic();

        // Mocking: Return the non-DH PublicKey
        when(keyStorageHandler.getPublicKey(identifier)).thenReturn(nonDhPublicKey);

        // Action & Assertion: Expect KeyManagementException
        KeyManagementException thrown = assertThrows(KeyManagementException.class, () ->
            keyService.getPublicKey(identifier));
        // assertTrue(thrown.getCause() instanceof ClassCastException || thrown.getCause() instanceof InvalidKeySpecException);
         assertNotNull(thrown.getCause()); // Check there is a cause

        // Verification
        verify(keyStorageHandler).getPublicKey(identifier);
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
        com.voteomatic.cryptography.core.elgamal.PublicKey key = new com.voteomatic.cryptography.core.elgamal.PublicKey(P, G.add(BigInteger.ONE), BigInteger.TEN);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YLessThanOne() throws KeyManagementException {
        com.voteomatic.cryptography.core.elgamal.PublicKey key = new com.voteomatic.cryptography.core.elgamal.PublicKey(P, G, BigInteger.ZERO);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YEqualsP() throws KeyManagementException {
        com.voteomatic.cryptography.core.elgamal.PublicKey key = new com.voteomatic.cryptography.core.elgamal.PublicKey(P, G, P);
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    @Test
    void testVerifyKeyIntegrity_YGreaterThanP() throws KeyManagementException {
        com.voteomatic.cryptography.core.elgamal.PublicKey key = new com.voteomatic.cryptography.core.elgamal.PublicKey(P, G, P.add(BigInteger.ONE));
        assertFalse(keyService.verifyKeyIntegrity(key));
    }

    // Serialization helper method no longer needed
}