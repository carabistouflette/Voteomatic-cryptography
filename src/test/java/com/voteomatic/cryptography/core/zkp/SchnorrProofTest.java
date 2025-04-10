package com.voteomatic.cryptography.core.zkp;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class SchnorrProofTest {

    private final BigInteger t_val = new BigInteger("12345"); // Example commitment t
    private final BigInteger s_val = new BigInteger("67890"); // Example response s

    @Test
    void constructorAndGetters() {
        SchnorrProof proof = new SchnorrProof(t_val, s_val);
        assertEquals(t_val, proof.getT());
        assertEquals(s_val, proof.getS());
    }

    @Test
    void constructor_nullT_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrProof(null, s_val);
        });
        assertEquals("Proof parameters t and s cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullS_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrProof(t_val, null);
        });
        assertEquals("Proof parameters t and s cannot be null", exception.getMessage());
    }

    @Test
    void equalsAndHashCode() {
        SchnorrProof proof1 = new SchnorrProof(t_val, s_val);
        SchnorrProof proof2 = new SchnorrProof(t_val, s_val);
        SchnorrProof proof3 = new SchnorrProof(t_val, BigInteger.ONE); // Different s
        SchnorrProof proof4 = new SchnorrProof(BigInteger.ZERO, s_val); // Different t

        // Reflexive
        assertEquals(proof1, proof1);
        assertEquals(proof1.hashCode(), proof1.hashCode());

        // Symmetric
        assertEquals(proof1, proof2);
        assertEquals(proof2, proof1);
        assertEquals(proof1.hashCode(), proof2.hashCode());

        // Transitive (implicit via proof1 <-> proof2)

        // Consistent
        assertEquals(proof1, proof2);
        assertEquals(proof1.hashCode(), proof2.hashCode());

        // Not equal to null
        assertNotEquals(null, proof1);

        // Not equal to different types
        assertNotEquals("a string", proof1);

        // Not equal with different values
        assertNotEquals(proof1, proof3);
        assertNotEquals(proof1.hashCode(), proof3.hashCode()); // Hash codes likely different
        assertNotEquals(proof1, proof4);
        assertNotEquals(proof1.hashCode(), proof4.hashCode());
    }

    @Test
    void testToString() {
        SchnorrProof proof = new SchnorrProof(t_val, s_val);
        String expectedString = "SchnorrProof{t=12345, s=67890}";
        assertEquals(expectedString, proof.toString());
    }
}