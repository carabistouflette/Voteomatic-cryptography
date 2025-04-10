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

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class KeyServiceImplTest {

    private KeyService keyService;
    private KeyStorageHandler keyStorageHandler;
    private SecureRandomGenerator secureRandomGenerator;

    // RFC 3526 Group 14 Parameters (or simpler ones for faster tests if needed)
    // Using smaller values for faster testing initially
    private static final BigInteger P = new BigInteger("23");
    private static final BigInteger G = new BigInteger("5");
    // private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    // private static final BigInteger G = BigInteger.valueOf(2);


    @BeforeEach
    void setUp() {
        secureRandomGenerator = new SecureRandomGeneratorImpl();
        keyStorageHandler = new InMemoryKeyStorageHandler();
        // Assuming KeyServiceImpl constructor takes (p, g, storageHandler, randomGenerator)
        keyService = new KeyServiceImpl(P, G, keyStorageHandler, secureRandomGenerator);
    }

    @Test
    void testGenerateKeyPair_Success() throws KeyManagementException {
        KeyPair keyPair = keyService.generateKeyPair();

        assertNotNull(keyPair, "Generated key pair should not be null");
        assertNotNull(keyPair.getPublicKey(), "Public key should not be null");
        assertNotNull(keyPair.getPrivateKey(), "Private key should not be null");

        PublicKey publicKey = keyPair.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivateKey();

        // Basic validation: Check if public key parameters match
        assertEquals(P, publicKey.getP(), "Public key P should match the service P");
        assertEquals(G, publicKey.getG(), "Public key G should match the service G");

        // Verify y = g^x mod p
        BigInteger expectedY = G.modPow(privateKey.getX(), P);
        assertEquals(expectedY, publicKey.getY(), "Public key Y should be g^x mod p");

        System.out.println("Generated Key Pair:");
        System.out.println("  Public Key (p): " + publicKey.getP());
        System.out.println("  Public Key (g): " + publicKey.getG());
        System.out.println("  Public Key (y): " + publicKey.getY());
        System.out.println("  Private Key (x): " + privateKey.getX());
    }

    @Test
    void testStoreAndRetrieveKeyPair_Success() throws KeyManagementException, DataHandlingException {
        KeyPair originalKeyPair = keyService.generateKeyPair();
        String identifier = "test-key-1";

        keyService.storeKeyPair(originalKeyPair, identifier);
        KeyPair retrievedKeyPair = keyService.retrieveKeyPair(identifier);

        assertNotNull(retrievedKeyPair, "Retrieved key pair should not be null");
        assertEquals(originalKeyPair, retrievedKeyPair, "Retrieved key pair should equal the original");
        assertEquals(originalKeyPair.getPublicKey(), retrievedKeyPair.getPublicKey(), "Public keys should match");
        assertEquals(originalKeyPair.getPrivateKey(), retrievedKeyPair.getPrivateKey(), "Private keys should match");
    }

    @Test
    void testStoreAndGetPublicKey_Success() throws KeyManagementException, DataHandlingException {
        KeyPair keyPair = keyService.generateKeyPair();
        String identifier = "test-key-pub-1";

        keyService.storeKeyPair(keyPair, identifier);
        PublicKey retrievedPublicKey = keyService.getPublicKey(identifier);

        assertNotNull(retrievedPublicKey, "Retrieved public key should not be null");
        assertEquals(keyPair.getPublicKey(), retrievedPublicKey, "Retrieved public key should equal the original public key");
    }

    @Test
    void testRetrieveKeyPair_NotFound() {
        String identifier = "non-existent-key";

        // Expect KeyManagementException or potentially DataHandlingException if storage layer throws it
        Exception exception = assertThrows(KeyManagementException.class, () -> {
            keyService.retrieveKeyPair(identifier);
        }, "Should throw KeyManagementException when key pair not found");

        // Optional: Check exception message if needed
        // assertTrue(exception.getMessage().contains(identifier));
        System.out.println("Caught expected exception: " + exception.getMessage());
    }

     @Test
     void testRetrievePublicKey_NotFound() {
         String identifier = "non-existent-public-key";

         Exception exception = assertThrows(KeyManagementException.class, () -> {
             keyService.getPublicKey(identifier);
         }, "Should throw KeyManagementException when public key not found");

         System.out.println("Caught expected exception for public key: " + exception.getMessage());
     }

    @Test
    void testVerifyKeyIntegrity_Success() throws KeyManagementException {
        // Test the verifyKeyIntegrity method implemented in KeyServiceImpl
        // If the method doesn't exist, this test should be removed or adapted.

        // Assuming a simple check for demonstration:
        KeyPair keyPair = keyService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublicKey();

        // Call the actual method
        boolean isIntegrityOk = keyService.verifyKeyIntegrity(publicKey);
        assertTrue(isIntegrityOk, "Key integrity verification should pass for a valid key generated by the service");

        // Test with a key having mismatched parameters (should fail)
        PublicKey mismatchedPKey = new PublicKey(P.add(BigInteger.ONE), G, publicKey.getY());
        assertFalse(keyService.verifyKeyIntegrity(mismatchedPKey), "Integrity check should fail for mismatched P");

        PublicKey mismatchedGKey = new PublicKey(P, G.add(BigInteger.ONE), publicKey.getY());
         assertFalse(keyService.verifyKeyIntegrity(mismatchedGKey), "Integrity check should fail for mismatched G");

         // Test with null key (should throw exception)
         assertThrows(KeyManagementException.class, () -> {
             keyService.verifyKeyIntegrity(null);
         }, "Should throw KeyManagementException for null public key");
    }
}