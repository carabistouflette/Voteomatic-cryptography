package com.voteomatic.cryptography.securityutils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class PrivateSigningKeyImplTest {

    private static PrivateKey jcaPrivateKey;
    private static final String ALGORITHM = "RSA"; // Example algorithm

    @BeforeAll
    static void setUp() throws NoSuchAlgorithmException {
        // Generate a sample JCA PrivateKey for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048); // Example key size
        KeyPair keyPair = keyGen.generateKeyPair();
        jcaPrivateKey = keyPair.getPrivate();
    }

    @Test
    void constructor_validKey_createsInstance() {
        PrivateSigningKeyImpl signingKey = new PrivateSigningKeyImpl(jcaPrivateKey);
        assertNotNull(signingKey);
        assertEquals(jcaPrivateKey, signingKey.getJcaPrivateKey());
    }

    @Test
    void constructor_nullKey_throwsException() {
        assertThrows(IllegalArgumentException.class, () -> {
            new PrivateSigningKeyImpl(null);
        });
    }

    @Test
    void getJcaPrivateKey_returnsCorrectKey() {
        PrivateSigningKeyImpl signingKey = new PrivateSigningKeyImpl(jcaPrivateKey);
        assertEquals(jcaPrivateKey, signingKey.getJcaPrivateKey());
    }

    @Test
    void getAlgorithm_returnsCorrectAlgorithm() {
        PrivateSigningKeyImpl signingKey = new PrivateSigningKeyImpl(jcaPrivateKey);
        assertEquals(ALGORITHM, signingKey.getAlgorithm());
    }

    // Note: PrivateKey.getEncoded() might return null if the key doesn't support encoding
    // or if there's no standard format (like PKCS#8). We assume RSA private keys support PKCS#8.
    @Test
    void getEncoded_returnsCorrectEncodingIfSupported() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateSigningKeyImpl signingKey = new PrivateSigningKeyImpl(jcaPrivateKey);
        byte[] encodedKey = signingKey.getEncoded(); // This delegates to jcaPrivateKey.getEncoded()

        if (encodedKey != null) {
            assertTrue(encodedKey.length > 0);
            // Verify the encoding by reconstructing the key
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            PrivateKey reconstructedKey = keyFactory.generatePrivate(keySpec);
            assertEquals(jcaPrivateKey, reconstructedKey);
        } else {
            // If encoding is not supported, the method should reflect that (e.g., return null or throw)
            // In this implementation, it returns jcaPrivateKey.getEncoded(), so we check for null.
            assertNull(encodedKey, "Encoded key should be null if not supported by the underlying JCA key");
            // Or, if the contract is to throw an exception:
            // assertThrows(UnsupportedOperationException.class, signingKey::getEncoded);
        }
    }
}