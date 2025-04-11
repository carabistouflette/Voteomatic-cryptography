package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.core.DomainParameters; // Added import
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class PrivateKeyTest {

    private final BigInteger p_val = new BigInteger("23"); // Example prime value
    private final BigInteger g_val = new BigInteger("5");  // Example generator value
    private final BigInteger q_val = p_val.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = 11
    private final DomainParameters params = new DomainParameters(p_val, g_val, q_val);
    private final BigInteger x_val = new BigInteger("6");  // Example private key value

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        PrivateKey privateKey = new PrivateKey(params, x_val);

        assertEquals(params, privateKey.getParams(), "getParams should return the DomainParameters object.");
        assertEquals(p_val, privateKey.getP(), "getP should return the prime modulus p from params.");
        assertEquals(g_val, privateKey.getG(), "getG should return the generator g from params.");
        assertEquals(q_val, privateKey.getQ(), "getQ should return the subgroup order q from params.");
        assertEquals(x_val, privateKey.getX(), "getX should return the private exponent x.");
    }

    @Test
    void constructor_NullParams_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PrivateKey(null, x_val),
                     "Constructor should throw NullPointerException if params is null.");
    }

    // Tests for null G is implicitly covered by null Params test now.

    @Test
    void constructor_NullX_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PrivateKey(params, null),
                     "Constructor should throw NullPointerException if x is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        PrivateKey key1 = new PrivateKey(params, x_val);
        assertTrue(key1.equals(key1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params, x_val); // Same values
        assertTrue(key1.equals(key2), "Objects with the same p, g, and x should be equal.");
    }

    @Test
    void equals_DifferentParamsP_ShouldReturnFalse() {
        BigInteger p2_val = new BigInteger("29"); // Different prime value
        DomainParameters params2 = new DomainParameters(p2_val, g_val, p2_val.subtract(BigInteger.ONE).divide(BigInteger.TWO)); // Different params
        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params2, x_val);
        assertFalse(key1.equals(key2), "Objects with different params (different p) should not be equal.");
    }

    @Test
    void equals_DifferentParamsG_ShouldReturnFalse() {
        BigInteger g2_val = new BigInteger("7"); // Different generator value
        DomainParameters params2 = new DomainParameters(p_val, g2_val, q_val); // Different params
        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params2, x_val);
        assertFalse(key1.equals(key2), "Objects with different params (different g) should not be equal.");
    }

    @Test
    void equals_DifferentX_ShouldReturnFalse() {
        BigInteger x2_val = new BigInteger("7"); // Different private key value
        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params, x2_val); // Same params, different x
        assertFalse(key1.equals(key2), "Objects with different x should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        PrivateKey key1 = new PrivateKey(params, x_val);
        assertFalse(key1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        PrivateKey key1 = new PrivateKey(params, x_val);
        Object other = new Object();
        assertFalse(key1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params, x_val); // Same values
        assertEquals(key1.hashCode(), key2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        BigInteger p2_val = new BigInteger("29");
        BigInteger g2_val = new BigInteger("7");
        BigInteger x2_val = new BigInteger("7");
        DomainParameters params2_p = new DomainParameters(p2_val, g_val, p2_val.subtract(BigInteger.ONE).divide(BigInteger.TWO));
        DomainParameters params2_g = new DomainParameters(p_val, g2_val, q_val);

        PrivateKey key1 = new PrivateKey(params, x_val);
        PrivateKey key2 = new PrivateKey(params2_p, x_val); // Different params (p)
        PrivateKey key3 = new PrivateKey(params2_g, x_val); // Different params (g)
        PrivateKey key4 = new PrivateKey(params, x2_val); // Different x

        assertNotEquals(key1.hashCode(), key2.hashCode(), "Hash code should likely differ if params differ (p).");
        assertNotEquals(key1.hashCode(), key3.hashCode(), "Hash code should likely differ if params differ (g).");
        assertNotEquals(key1.hashCode(), key4.hashCode(), "Hash code should likely differ if x differs.");
    }

    @Test
    void toString_ContainsFieldValuesAndRedactsX() {
        PrivateKey privateKey = new PrivateKey(params, x_val);
        String str = privateKey.toString();

        // Check if the params object's toString is included, and x is redacted
        assertTrue(str.contains("params=" + params.toString()), "toString should contain the DomainParameters object string representation.");
        assertTrue(str.contains("x=[REDACTED]"), "toString should contain 'x=[REDACTED]'.");
        assertFalse(str.contains("x=" + x_val), "toString should NOT contain the actual value of x.");
        assertTrue(str.startsWith("PrivateKey{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}