package com.voteomatic.cryptography.core.elgamal;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class PrivateKeyTest {

    private final BigInteger p = new BigInteger("23"); // Example prime
    private final BigInteger g = new BigInteger("5");  // Example generator
    private final BigInteger x = new BigInteger("6");  // Example private key

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        PrivateKey privateKey = new PrivateKey(p, g, x);

        assertEquals(p, privateKey.getP(), "getP should return the prime modulus p.");
        assertEquals(g, privateKey.getG(), "getG should return the generator g.");
        assertEquals(x, privateKey.getX(), "getX should return the private exponent x.");
    }

    @Test
    void constructor_NullP_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PrivateKey(null, g, x),
                     "Constructor should throw NullPointerException if p is null.");
    }

    @Test
    void constructor_NullG_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PrivateKey(p, null, x),
                     "Constructor should throw NullPointerException if g is null.");
    }

    @Test
    void constructor_NullX_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PrivateKey(p, g, null),
                     "Constructor should throw NullPointerException if x is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        PrivateKey key1 = new PrivateKey(p, g, x);
        assertTrue(key1.equals(key1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p, g, x); // Same values
        assertTrue(key1.equals(key2), "Objects with the same p, g, and x should be equal.");
    }

    @Test
    void equals_DifferentP_ShouldReturnFalse() {
        BigInteger p2 = new BigInteger("29"); // Different prime
        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p2, g, x);
        assertFalse(key1.equals(key2), "Objects with different p should not be equal.");
    }

    @Test
    void equals_DifferentG_ShouldReturnFalse() {
        BigInteger g2 = new BigInteger("7"); // Different generator
        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p, g2, x);
        assertFalse(key1.equals(key2), "Objects with different g should not be equal.");
    }

    @Test
    void equals_DifferentX_ShouldReturnFalse() {
        BigInteger x2 = new BigInteger("7"); // Different private key
        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p, g, x2);
        assertFalse(key1.equals(key2), "Objects with different x should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        PrivateKey key1 = new PrivateKey(p, g, x);
        assertFalse(key1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        PrivateKey key1 = new PrivateKey(p, g, x);
        Object other = new Object();
        assertFalse(key1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p, g, x); // Same values
        assertEquals(key1.hashCode(), key2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        BigInteger p2 = new BigInteger("29");
        BigInteger g2 = new BigInteger("7");
        BigInteger x2 = new BigInteger("7");

        PrivateKey key1 = new PrivateKey(p, g, x);
        PrivateKey key2 = new PrivateKey(p2, g, x); // Different p
        PrivateKey key3 = new PrivateKey(p, g2, x); // Different g
        PrivateKey key4 = new PrivateKey(p, g, x2); // Different x

        assertNotEquals(key1.hashCode(), key2.hashCode(), "Hash code should likely differ if p differs.");
        assertNotEquals(key1.hashCode(), key3.hashCode(), "Hash code should likely differ if g differs.");
        assertNotEquals(key1.hashCode(), key4.hashCode(), "Hash code should likely differ if x differs.");
    }

    @Test
    void toString_ContainsFieldValuesAndRedactsX() {
        PrivateKey privateKey = new PrivateKey(p, g, x);
        String str = privateKey.toString();

        assertTrue(str.contains("p=" + p), "toString should contain the value of p.");
        assertTrue(str.contains("g=" + g), "toString should contain the value of g.");
        assertTrue(str.contains("x=[REDACTED]"), "toString should contain 'x=[REDACTED]'.");
        assertFalse(str.contains("x=" + x), "toString should NOT contain the actual value of x.");
        assertTrue(str.startsWith("PrivateKey{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}