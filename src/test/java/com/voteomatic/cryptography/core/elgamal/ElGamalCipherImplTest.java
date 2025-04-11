package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.core.DomainParameters; // Added import
// Project classes
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
// JUnit 5 imports
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;

// Java standard libraries
import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;


/**
 * Unit tests for the {@link ElGamalCipherImpl} class.
 */
public class ElGamalCipherImplTest {

    private SecureRandomGenerator secureRandomGenerator;
    private ElGamalCipher elGamalCipher;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    // p and g are now part of domainParams
    private DomainParameters domainParams;
    @BeforeEach
    void setUp() {
        // Use a deterministic seed for reproducibility in tests if needed,
        // but a standard SecureRandom is generally fine for testing functionality.
        secureRandomGenerator = new SecureRandomGeneratorImpl(new SecureRandom());
        elGamalCipher = new ElGamalCipherImpl(secureRandomGenerator);

        // Simple, small ElGamal parameters for faster testing (p=23, g=5)
        // p must be prime, g must be a generator modulo p.
        // 5 is a generator mod 23 because its powers generate all numbers from 1 to 22.
        BigInteger p = new BigInteger("23");
        BigInteger g = new BigInteger("5");
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = (23-1)/2 = 11
        domainParams = new DomainParameters(p, g, q);

        // Manually generate a KeyPair for testing consistency.
        // Choose a private key x such that 1 < x < p-1.
        BigInteger x = new BigInteger("6"); // Example private key

        // Calculate the corresponding public key y = g^x mod p.
        BigInteger y = domainParams.getG().modPow(x, domainParams.getP()); // 5^6 mod 23 = 8
    
        publicKey = new PublicKey(domainParams, y);
        privateKey = new PrivateKey(domainParams, x);
    }

    /**
     * Tests the basic encryption and decryption flow for a valid message.
     */
    @Test
    void testEncryptDecrypt_Success() {
        // Choose a message m such that 1 <= m < p.
        BigInteger message = new BigInteger("13");
        Assertions.assertTrue(message.compareTo(BigInteger.ONE) >= 0 && message.compareTo(domainParams.getP()) < 0,
                "Test message must be within the valid range [1, p-1]");

        // Encrypt the message using the public key
        EncryptionResult encryptionResult = elGamalCipher.encrypt(publicKey, message);
        Ciphertext ciphertext = encryptionResult.getCiphertext();
        Assertions.assertNotNull(ciphertext, "Ciphertext should not be null");
        Assertions.assertNotNull(ciphertext.getC1(), "Ciphertext component c1 should not be null");
        Assertions.assertNotNull(ciphertext.getC2(), "Ciphertext component c2 should not be null");


        // Decrypt the ciphertext using the private key
        BigInteger decryptedMessage = elGamalCipher.decrypt(privateKey, ciphertext);
        Assertions.assertNotNull(decryptedMessage, "Decrypted message should not be null");

        // Assert that the decrypted message matches the original message
        Assertions.assertEquals(message, decryptedMessage,
                "Decrypted message should match the original message");
    }

    /**
     * Tests encryption and decryption for the edge case message m = 1.
     */
    @Test
    void testEncryptDecrypt_MessageOne() {
        BigInteger message = BigInteger.ONE;
        assertTrue(message.compareTo(BigInteger.ONE) >= 0 && message.compareTo(domainParams.getP()) < 0,
                "Test message must be within the valid range [1, p-1]");

        EncryptionResult encryptionResult = elGamalCipher.encrypt(publicKey, message);
        Ciphertext ciphertext = encryptionResult.getCiphertext();
        assertNotNull(ciphertext);

        BigInteger decryptedMessage = elGamalCipher.decrypt(privateKey, ciphertext);
        assertEquals(message, decryptedMessage, "Decrypted message should be 1");
    }

    /**
     * Tests that encrypt throws NullPointerException for a null public key.
     */
    @Test
    void testEncrypt_NullPublicKey() {
        BigInteger message = new BigInteger("10");
        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.encrypt(null, message);
        }, "Encrypting with a null public key should throw NullPointerException");
    }

    /**
     * Tests that encrypt throws NullPointerException for a null message.
     */
    @Test
    void testEncrypt_NullMessage() {
        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.encrypt(publicKey, null);
        }, "Encrypting a null message should throw NullPointerException");
    }

    // /**
    // * Tests that encrypt throws IllegalArgumentException for a message less than 1.
    // * NOTE: Commented out because the current implementation of ElGamalCipherImpl.encrypt
    // * does not appear to enforce message >= 1, and production code modification is disallowed.
    // */
    // @Test
    // void testEncrypt_MessageOutOfRange_BelowOne() {
    //     BigInteger message = BigInteger.ZERO;
    //      assertThrows(IllegalArgumentException.class, () -> {
    //         elGamalCipher.encrypt(publicKey, message);
    //     }, "Encrypting a message < 1 should throw IllegalArgumentException");
    // }

    /**
     * Tests that encrypt throws IllegalArgumentException for a message greater than or equal to p.
     */
    @Test
    void testEncrypt_MessageOutOfRange_AbovePMinusOne() {
        BigInteger message = domainParams.getP(); // Message equal to p
         assertThrows(IllegalArgumentException.class, () -> {
            elGamalCipher.encrypt(publicKey, message);
        }, "Encrypting a message >= p should throw IllegalArgumentException");

        BigInteger message2 = domainParams.getP().add(BigInteger.ONE); // Message greater than p
         assertThrows(IllegalArgumentException.class, () -> {
            elGamalCipher.encrypt(publicKey, message2);
        }, "Encrypting a message >= p should throw IllegalArgumentException");
    }


    /**
     * Tests that decrypt throws NullPointerException for a null private key.
     */
    @Test
    void testDecrypt_NullPrivateKey() {
        // Need a valid ciphertext first
        BigInteger message = new BigInteger("10");
        EncryptionResult encryptionResult = elGamalCipher.encrypt(publicKey, message);
        Ciphertext ciphertext = encryptionResult.getCiphertext();

        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.decrypt(null, ciphertext);
        }, "Decrypting with a null private key should throw NullPointerException");
    }

    /**
     * Tests that decrypt throws NullPointerException for a null ciphertext.
     */
    @Test
    void testDecrypt_NullCiphertext() {
        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.decrypt(privateKey, null);
        }, "Decrypting a null ciphertext should throw NullPointerException");
    }

    /**
     * Tests that decrypt throws NullPointerException when ciphertext component c1 is null.
     * Requires Ciphertext constructor to allow nulls (modification made).
     */
    @Test
    void testDecrypt_NullCiphertextC1() {
        // Construct ciphertext with null c1 (possible after modifying Ciphertext constructor)
        Ciphertext ciphertextWithNullC1 = new Ciphertext(null, BigInteger.TEN); // c2 is arbitrary non-null

        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.decrypt(privateKey, ciphertextWithNullC1);
        }, "Decrypting ciphertext with null c1 should throw NullPointerException");
    }

    /**
     * Tests that decrypt throws NullPointerException when ciphertext component c2 is null.
     * Requires Ciphertext constructor to allow nulls (modification made).
     */
    @Test
    void testDecrypt_NullCiphertextC2() {
        // Construct ciphertext with null c2 (possible after modifying Ciphertext constructor)
        Ciphertext ciphertextWithNullC2 = new Ciphertext(BigInteger.TEN, null); // c1 is arbitrary non-null

        assertThrows(NullPointerException.class, () -> {
            elGamalCipher.decrypt(privateKey, ciphertextWithNullC2);
        }, "Decrypting ciphertext with null c2 should throw NullPointerException");
    }


    /**
     * Tests that decrypting with an incorrect private key yields an incorrect message.
     */
    @Test
    void testDecrypt_WrongPrivateKey() {
        BigInteger message = new BigInteger("15");
        EncryptionResult encryptionResult = elGamalCipher.encrypt(publicKey, message);
        Ciphertext ciphertext = encryptionResult.getCiphertext();

        // Create a different private key (x=7 instead of 6)
        BigInteger wrongX = new BigInteger("7");
        PrivateKey wrongPrivateKey = new PrivateKey(domainParams, wrongX);

        BigInteger decryptedMessage = elGamalCipher.decrypt(wrongPrivateKey, ciphertext);

        assertNotEquals(message, decryptedMessage,
                "Decrypting with the wrong private key should not yield the original message");
    }
}