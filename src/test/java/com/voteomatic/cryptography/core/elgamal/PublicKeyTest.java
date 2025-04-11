package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.core.DomainParameters; // Added import
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class PublicKeyTest {

    // Example values (consistent with PrivateKeyTest for potential future integration tests)
    private final BigInteger p_val = new BigInteger("23"); // Example prime value
    private final BigInteger g_val = new BigInteger("5");  // Example generator value
    private final BigInteger q_val = p_val.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = 11
    private final DomainParameters params = new DomainParameters(p_val, g_val, q_val);
    // y = g^x mod p = 5^6 mod 23 = 15625 mod 23 = 8
    private final BigInteger y_val = new BigInteger("8");  // Example public value

    @Test
    void constructorAndGetters_ValidInput_ShouldSucceed() {
        PublicKey publicKey = new PublicKey(params, y_val);

        assertEquals(params, publicKey.getParams(), "getParams should return the DomainParameters object.");
        assertEquals(p_val, publicKey.getP(), "getP should return the prime modulus p from params.");
        assertEquals(g_val, publicKey.getG(), "getG should return the generator g from params.");
        assertEquals(q_val, publicKey.getQ(), "getQ should return the subgroup order q from params.");
        assertEquals(y_val, publicKey.getY(), "getY should return the public value y.");
    }

    @Test
    void constructor_NullParams_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PublicKey(null, y_val),
                     "Constructor should throw NullPointerException if params is null.");
    }

    // Tests for null G is implicitly covered by null Params test now.

    @Test
    void constructor_NullY_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new PublicKey(params, null),
                     "Constructor should throw NullPointerException if y is null.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        PublicKey key1 = new PublicKey(params, y_val);
        assertTrue(key1.equals(key1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params, y_val); // Same values
        assertTrue(key1.equals(key2), "Objects with the same p, g, and y should be equal.");
    }

    @Test
    void equals_DifferentParamsP_ShouldReturnFalse() {
        BigInteger p2_val = new BigInteger("29"); // Different prime value
        DomainParameters params2 = new DomainParameters(p2_val, g_val, p2_val.subtract(BigInteger.ONE).divide(BigInteger.TWO)); // Different params
        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params2, y_val);
        assertFalse(key1.equals(key2), "Objects with different params (different p) should not be equal.");
    }

    @Test
    void equals_DifferentParamsG_ShouldReturnFalse() {
        BigInteger g2_val = new BigInteger("7"); // Different generator value
        DomainParameters params2 = new DomainParameters(p_val, g2_val, q_val); // Different params
        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params2, y_val);
        assertFalse(key1.equals(key2), "Objects with different params (different g) should not be equal.");
    }

    @Test
    void equals_DifferentY_ShouldReturnFalse() {
        BigInteger y2_val = new BigInteger("9"); // Different public value
        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params, y2_val); // Same params, different y
        assertFalse(key1.equals(key2), "Objects with different y should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        PublicKey key1 = new PublicKey(params, y_val);
        assertFalse(key1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        PublicKey key1 = new PublicKey(params, y_val);
        Object other = new Object();
        assertFalse(key1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params, y_val); // Same values
        assertEquals(key1.hashCode(), key2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        BigInteger p2_val = new BigInteger("29");
        BigInteger g2_val = new BigInteger("7");
        BigInteger y2_val = new BigInteger("9");
        DomainParameters params2_p = new DomainParameters(p2_val, g_val, p2_val.subtract(BigInteger.ONE).divide(BigInteger.TWO));
        DomainParameters params2_g = new DomainParameters(p_val, g2_val, q_val);

        PublicKey key1 = new PublicKey(params, y_val);
        PublicKey key2 = new PublicKey(params2_p, y_val); // Different params (p)
        PublicKey key3 = new PublicKey(params2_g, y_val); // Different params (g)
        PublicKey key4 = new PublicKey(params, y2_val); // Different y

        assertNotEquals(key1.hashCode(), key2.hashCode(), "Hash code should likely differ if params differ (p).");
        assertNotEquals(key1.hashCode(), key3.hashCode(), "Hash code should likely differ if params differ (g).");
        assertNotEquals(key1.hashCode(), key4.hashCode(), "Hash code should likely differ if y differs.");
    }

    @Test
    void toString_ContainsFieldValues() {
        PublicKey publicKey = new PublicKey(params, y_val);
        String str = publicKey.toString();

        // Check if the params object's toString is included, and the y value
        assertTrue(str.contains("params=" + params.toString()), "toString should contain the DomainParameters object string representation.");
        assertTrue(str.contains("y=" + y_val), "toString should contain the value of y.");
        assertTrue(str.startsWith("PublicKey{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}