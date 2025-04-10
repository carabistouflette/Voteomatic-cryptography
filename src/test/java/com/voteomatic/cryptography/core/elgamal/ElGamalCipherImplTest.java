package com.voteomatic.cryptography.core.elgamal;

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

/**
 * Unit tests for the {@link ElGamalCipherImpl} class.
 */
public class ElGamalCipherImplTest {

    private SecureRandomGenerator secureRandomGenerator;
    private ElGamalCipher elGamalCipher;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private BigInteger p; // Prime modulus
    private BigInteger g; // Generator

    @BeforeEach
    void setUp() {
        // Use a deterministic seed for reproducibility in tests if needed,
        // but a standard SecureRandom is generally fine for testing functionality.
        secureRandomGenerator = new SecureRandomGeneratorImpl(new SecureRandom());
        elGamalCipher = new ElGamalCipherImpl(secureRandomGenerator);

        // Simple, small ElGamal parameters for faster testing (p=23, g=5)
        // p must be prime, g must be a generator modulo p.
        // 5 is a generator mod 23 because its powers generate all numbers from 1 to 22.
        p = new BigInteger("23");
        g = new BigInteger("5");

        // Manually generate a KeyPair for testing consistency.
        // Choose a private key x such that 1 < x < p-1.
        BigInteger x = new BigInteger("6"); // Example private key

        // Calculate the corresponding public key y = g^x mod p.
        BigInteger y = g.modPow(x, p); // 5^6 mod 23 = 8

        publicKey = new PublicKey(p, g, y);
        privateKey = new PrivateKey(p, g, x);
    }

    /**
     * Tests the basic encryption and decryption flow for a valid message.
     */
    @Test
    void testEncryptDecrypt_Success() {
        // Choose a message m such that 1 <= m < p.
        BigInteger message = new BigInteger("13");
        Assertions.assertTrue(message.compareTo(BigInteger.ONE) >= 0 && message.compareTo(p) < 0,
                "Test message must be within the valid range [1, p-1]");

        // Encrypt the message using the public key
        Ciphertext ciphertext = elGamalCipher.encrypt(publicKey, message);
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

    // --- To be added ---

    // @Test
    // void testEncryptDecrypt_MessageOne() { ... }

    // @Test
    // void testEncrypt_NullPublicKey() { ... }

    // @Test
    // void testEncrypt_NullMessage() { ... }

    // @Test
    // void testDecrypt_NullPrivateKey() { ... }

    // @Test
    // void testDecrypt_NullCiphertext() { ... }
}