package com.voteomatic.cryptography.core.zkp.schnorr;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class SchnorrWitnessTest {

  private final BigInteger x = new BigInteger("7"); // Example secret key x

  @Test
  void constructorAndGetter() {
    SchnorrWitness witness = SchnorrWitness.create(x);
    assertEquals(x, witness.getSecretValue()); // Updated method call
  }

  @Test
  void constructor_nullX_throwsException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrWitness.create(null);
            });
    assertEquals(
        "Witness parameter secretValue cannot be null",
        exception.getMessage()); // Updated parameter name
  }

  @Test
  void equalsAndHashCode() {
    SchnorrWitness witness1 = SchnorrWitness.create(x);
    SchnorrWitness witness2 = SchnorrWitness.create(x);
    SchnorrWitness witness3 = SchnorrWitness.create(BigInteger.TEN); // Different x

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
    SchnorrWitness witness = SchnorrWitness.create(x);
    // The toString() method correctly hides the secret value 'x'.
    String expectedString = "SchnorrWitness{secretValue=HIDDEN}"; // Updated parameter name
    // If it hides the value, it might be something like:
    // String expectedString = "SchnorrWitness{secretValue=********}";
    assertEquals(expectedString, witness.toString());
  }
}
