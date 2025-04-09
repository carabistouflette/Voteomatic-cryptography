package com.voteomatic.cryptography.core.elgamal;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class PublicKeyTest {

    // Example values (consistent with PrivateKeyTest for potential future integration tests)
    private final BigInteger p = new BigInteger("23"); // Example prime
    private final BigInteger g = new BigInteger("5");  // Example generator
    // y = g^x mod p = 5^6 mod 23 = 15625 mod 23 = 8
    private final BigInteger y = new BigInteger("8");  // Example public value

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        PublicKey publicKey = new PublicKey(p, g, y);

        assertEquals(p, publicKey.getP(), "getP should return the prime modulus p.");
        assertEquals(g, publicKey.getG(), "getG should return the generator g.");
        assertEquals(y, publicKey.getY(), "getY should return the public value y.");
    }

    @Test
    void constructor_NullP_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PublicKey(null, g, y),
                     "Constructor should throw NullPointerException if p is null.");
    }

    @Test
    void constructor_NullG_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PublicKey(p, null, y),
                     "Constructor should throw NullPointerException if g is null.");
    }

    @Test
    void constructor_NullY_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PublicKey(p, g, null),
                     "Constructor should throw NullPointerException if y is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        PublicKey key1 = new PublicKey(p, g, y);
        assertTrue(key1.equals(key1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p, g, y); // Same values
        assertTrue(key1.equals(key2), "Objects with the same p, g, and y should be equal.");
    }

    @Test
    void equals_DifferentP_ShouldReturnFalse() {
        BigInteger p2 = new BigInteger("29"); // Different prime
        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p2, g, y);
        assertFalse(key1.equals(key2), "Objects with different p should not be equal.");
    }

    @Test
    void equals_DifferentG_ShouldReturnFalse() {
        BigInteger g2 = new BigInteger("7"); // Different generator
        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p, g2, y);
        assertFalse(key1.equals(key2), "Objects with different g should not be equal.");
    }

    @Test
    void equals_DifferentY_ShouldReturnFalse() {
        BigInteger y2 = new BigInteger("9"); // Different public value
        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p, g, y2);
        assertFalse(key1.equals(key2), "Objects with different y should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        PublicKey key1 = new PublicKey(p, g, y);
        assertFalse(key1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        PublicKey key1 = new PublicKey(p, g, y);
        Object other = new Object();
        assertFalse(key1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p, g, y); // Same values
        assertEquals(key1.hashCode(), key2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        BigInteger p2 = new BigInteger("29");
        BigInteger g2 = new BigInteger("7");
        BigInteger y2 = new BigInteger("9");

        PublicKey key1 = new PublicKey(p, g, y);
        PublicKey key2 = new PublicKey(p2, g, y); // Different p
        PublicKey key3 = new PublicKey(p, g2, y); // Different g
        PublicKey key4 = new PublicKey(p, g, y2); // Different y

        assertNotEquals(key1.hashCode(), key2.hashCode(), "Hash code should likely differ if p differs.");
        assertNotEquals(key1.hashCode(), key3.hashCode(), "Hash code should likely differ if g differs.");
        assertNotEquals(key1.hashCode(), key4.hashCode(), "Hash code should likely differ if y differs.");
    }

    @Test
    void toString_ContainsFieldValues() {
        PublicKey publicKey = new PublicKey(p, g, y);
        String str = publicKey.toString();

        assertTrue(str.contains("p=" + p), "toString should contain the value of p.");
        assertTrue(str.contains("g=" + g), "toString should contain the value of g.");
        assertTrue(str.contains("y=" + y), "toString should contain the value of y.");
        assertTrue(str.startsWith("PublicKey{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}