package com.voteomatic.cryptography.core.zkp;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class SchnorrWitnessTest {

    private final BigInteger x = new BigInteger("7"); // Example secret key x

    @Test
    void constructorAndGetter() {
        SchnorrWitness witness = new SchnorrWitness(x);
        assertEquals(x, witness.getX());
    }

    @Test
    void constructor_nullX_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrWitness(null);
        });
        assertEquals("Witness parameter x cannot be null", exception.getMessage());
    }

    @Test
    void equalsAndHashCode() {
        SchnorrWitness witness1 = new SchnorrWitness(x);
        SchnorrWitness witness2 = new SchnorrWitness(x);
        SchnorrWitness witness3 = new SchnorrWitness(BigInteger.TEN); // Different x

        // Reflexive
        assertEquals(witness1, witness1);
        assertEquals(witness1.hashCode(), witness1.hashCode());

        // Symmetric
        assertEquals(witness1, witness2);
        assertEquals(witness2, witness1);
        assertEquals(witness1.hashCode(), witness2.hashCode());

        // Transitive (implicit via witness1 <-> witness2)

        // Consistent
        assertEquals(witness1, witness2);
        assertEquals(witness1.hashCode(), witness2.hashCode());

        // Not equal to null
        assertNotEquals(null, witness1);

        // Not equal to different types
        assertNotEquals("a string", witness1);

        // Not equal with different values
        assertNotEquals(witness1, witness3);
        assertNotEquals(witness1.hashCode(), witness3.hashCode()); // Hash codes likely different
    }

    @Test
    void testToString() {
        SchnorrWitness witness = new SchnorrWitness(x);
        // The toString() method correctly hides the secret value 'x'.
        String expectedString = "SchnorrWitness{x=HIDDEN}";
        // If it hides the value, it might be something like:
        // String expectedString = "SchnorrWitness{x=********}";
        assertEquals(expectedString, witness.toString());
    }
}