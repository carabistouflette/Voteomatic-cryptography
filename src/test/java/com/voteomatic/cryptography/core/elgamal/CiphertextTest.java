package com.voteomatic.cryptography.core.elgamal;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class CiphertextTest {

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        BigInteger c1 = BigInteger.valueOf(123);
        BigInteger c2 = BigInteger.valueOf(456);
        Ciphertext ciphertext = new Ciphertext(c1, c2);

        assertEquals(c1, ciphertext.getC1(), "getC1 should return the value passed to the constructor.");
        assertEquals(c2, ciphertext.getC2(), "getC2 should return the value passed to the constructor.");
    }

    @Test
    void constructor_NullC1_ShouldThrowNullPointerException() {
        BigInteger c2 = BigInteger.valueOf(456);
        assertThrows(NullPointerException.class, () -> new Ciphertext(null, c2),
                     "Constructor should throw NullPointerException if c1 is null.");
    }

    @Test
    void constructor_NullC2_ShouldThrowNullPointerException() {
        BigInteger c1 = BigInteger.valueOf(123);
        assertThrows(NullPointerException.class, () -> new Ciphertext(c1, null),
                     "Constructor should throw NullPointerException if c2 is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1, c2);
        assertTrue(ct1.equals(ct1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1, c2);
        Ciphertext ct2 = new Ciphertext(c1, c2); // Same values
        assertTrue(ct1.equals(ct2), "Objects with the same c1 and c2 should be equal.");
    }

    @Test
    void equals_DifferentC1_ShouldReturnFalse() {
        BigInteger c1a = BigInteger.valueOf(10);
        BigInteger c1b = BigInteger.valueOf(11);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1a, c2);
        Ciphertext ct2 = new Ciphertext(c1b, c2);
        assertFalse(ct1.equals(ct2), "Objects with different c1 should not be equal.");
    }

    @Test
    void equals_DifferentC2_ShouldReturnFalse() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2a = BigInteger.valueOf(20);
        BigInteger c2b = BigInteger.valueOf(21);
        Ciphertext ct1 = new Ciphertext(c1, c2a);
        Ciphertext ct2 = new Ciphertext(c1, c2b);
        assertFalse(ct1.equals(ct2), "Objects with different c2 should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1, c2);
        assertFalse(ct1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1, c2);
        Object other = new Object();
        assertFalse(ct1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        BigInteger c1 = BigInteger.valueOf(10);
        BigInteger c2 = BigInteger.valueOf(20);
        Ciphertext ct1 = new Ciphertext(c1, c2);
        Ciphertext ct2 = new Ciphertext(c1, c2); // Same values
        assertEquals(ct1.hashCode(), ct2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        // Note: Hash collisions are possible, but unlikely with simple changes.
        // This test mainly ensures the hash code changes when fields change.
        BigInteger c1a = BigInteger.valueOf(10);
        BigInteger c1b = BigInteger.valueOf(11);
        BigInteger c2a = BigInteger.valueOf(20);
        BigInteger c2b = BigInteger.valueOf(21);

        Ciphertext ct1 = new Ciphertext(c1a, c2a);
        Ciphertext ct2 = new Ciphertext(c1b, c2a); // Different c1
        Ciphertext ct3 = new Ciphertext(c1a, c2b); // Different c2

        assertNotEquals(ct1.hashCode(), ct2.hashCode(), "Hash code should likely differ if c1 differs.");
        assertNotEquals(ct1.hashCode(), ct3.hashCode(), "Hash code should likely differ if c2 differs.");
    }

    @Test
    void toString_ContainsFieldValues() {
        BigInteger c1 = BigInteger.valueOf(987);
        BigInteger c2 = BigInteger.valueOf(654);
        Ciphertext ciphertext = new Ciphertext(c1, c2);
        String str = ciphertext.toString();

        assertTrue(str.contains("c1=" + c1), "toString should contain the value of c1.");
        assertTrue(str.contains("c2=" + c2), "toString should contain the value of c2.");
        assertTrue(str.startsWith("Ciphertext{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}