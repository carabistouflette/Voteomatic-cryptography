package com.voteomatic.cryptography.securityutils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;

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
        assertThrows(NullPointerException.class, () -> { // Corrected expected exception
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
}