package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class KeyPairTest {

    private PublicKey publicKey1;
    private PrivateKey privateKey1;
    private PublicKey publicKey2; // Different public key
    private PrivateKey privateKey2; // Different private key
    private KeyPair keyPair1;

    @BeforeEach
    void setUp() {
        BigInteger p1 = new BigInteger("23");
        BigInteger g1 = new BigInteger("5");
        BigInteger x1 = new BigInteger("6");
        BigInteger y1 = new BigInteger("8"); // g1^x1 mod p1

        BigInteger p2 = new BigInteger("29"); // Different params
        BigInteger g2 = new BigInteger("2");
        BigInteger x2 = new BigInteger("7");
        BigInteger y2 = new BigInteger("12"); // g2^x2 mod p2 (2^7 = 128 mod 29 = 12)

        publicKey1 = new PublicKey(p1, g1, y1);
        privateKey1 = new PrivateKey(p1, g1, x1);
        publicKey2 = new PublicKey(p2, g2, y2); // Different key
        privateKey2 = new PrivateKey(p2, g2, x2); // Different key

        keyPair1 = new KeyPair(publicKey1, privateKey1);
    }

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        assertEquals(publicKey1, keyPair1.getPublicKey(), "getPublicKey should return the public key passed to the constructor.");
        assertEquals(privateKey1, keyPair1.getPrivateKey(), "getPrivateKey should return the private key passed to the constructor.");
    }

    @Test
    void constructor_NullPublicKey_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new KeyPair(null, privateKey1),
                     "Constructor should throw NullPointerException if publicKey is null.");
    }

    @Test
    void constructor_NullPrivateKey_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new KeyPair(publicKey1, null),
                     "Constructor should throw NullPointerException if privateKey is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        assertTrue(keyPair1.equals(keyPair1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        KeyPair keyPair2 = new KeyPair(publicKey1, privateKey1); // Same keys
        assertTrue(keyPair1.equals(keyPair2), "KeyPairs with the same public and private keys should be equal.");
    }

    @Test
    void equals_DifferentPublicKey_ShouldReturnFalse() {
        KeyPair keyPair2 = new KeyPair(publicKey2, privateKey1); // Different public key
        assertFalse(keyPair1.equals(keyPair2), "KeyPairs with different public keys should not be equal.");
    }

    @Test
    void equals_DifferentPrivateKey_ShouldReturnFalse() {
        KeyPair keyPair2 = new KeyPair(publicKey1, privateKey2); // Different private key
        assertFalse(keyPair1.equals(keyPair2), "KeyPairs with different private keys should not be equal.");
    }

    @Test
    void equals_DifferentBothKeys_ShouldReturnFalse() {
        KeyPair keyPair2 = new KeyPair(publicKey2, privateKey2); // Different keys
        assertFalse(keyPair1.equals(keyPair2), "KeyPairs with different public and private keys should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        assertFalse(keyPair1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        Object other = new Object();
        assertFalse(keyPair1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        KeyPair keyPair2 = new KeyPair(publicKey1, privateKey1); // Same keys
        assertEquals(keyPair1.hashCode(), keyPair2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        KeyPair keyPair2 = new KeyPair(publicKey2, privateKey1); // Different public key
        KeyPair keyPair3 = new KeyPair(publicKey1, privateKey2); // Different private key

        assertNotEquals(keyPair1.hashCode(), keyPair2.hashCode(), "Hash code should likely differ if public key differs.");
        assertNotEquals(keyPair1.hashCode(), keyPair3.hashCode(), "Hash code should likely differ if private key differs.");
    }
}