package com.voteomatic.cryptography.core.zkp;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class DisjunctiveChaumPedersenWitnessTest {

  private final BigInteger sampleR = BigInteger.valueOf(12345);

  @Test
  void constructor_validInputV0_success() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertNotNull(witness);
    assertEquals(sampleR, witness.getR());
    assertEquals(0, witness.getV());
  }

  @Test
  void constructor_validInputV1_success() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    assertNotNull(witness);
    assertEquals(sampleR, witness.getR());
    assertEquals(1, witness.getV());
  }

  @Test
  void constructor_nullR_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              DisjunctiveChaumPedersenWitness.create(null, 0);
            });
    assertEquals("Randomness r cannot be null", exception.getMessage());
  }

  @Test
  void constructor_invalidV_throwsIllegalArgumentException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              DisjunctiveChaumPedersenWitness.create(sampleR, 2); // Invalid v
            });
    assertEquals("Message index v must be 0 or 1", exception.getMessage());

    exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              DisjunctiveChaumPedersenWitness.create(sampleR, -1); // Invalid v
            });
    assertEquals("Message index v must be 0 or 1", exception.getMessage());
  }

  @Test
  void getR_returnsCorrectValue() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertEquals(sampleR, witness.getR());
  }

  @Test
  void getV_returnsCorrectValue() {
    DisjunctiveChaumPedersenWitness witness0 = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertEquals(0, witness0.getV());
    DisjunctiveChaumPedersenWitness witness1 = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    assertEquals(1, witness1.getV());
  }

  @Test
  void equals_sameObject_returnsTrue() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertTrue(witness.equals(witness));
  }

  @Test
  void equals_nullObject_returnsFalse() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertFalse(witness.equals(null));
  }

  @Test
  void equals_differentClass_returnsFalse() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertFalse(witness.equals("a string"));
  }

  @Test
  void equals_equalObjects_returnsTrue() {
    DisjunctiveChaumPedersenWitness witness1 = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    DisjunctiveChaumPedersenWitness witness2 = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    assertTrue(witness1.equals(witness2));
  }

  @Test
  void equals_differentR_returnsFalse() {
    DisjunctiveChaumPedersenWitness witness1 = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    DisjunctiveChaumPedersenWitness witness2 =
        DisjunctiveChaumPedersenWitness.create(BigInteger.TEN, 0);
    assertFalse(witness1.equals(witness2));
  }

  @Test
  void equals_differentV_returnsFalse() {
    DisjunctiveChaumPedersenWitness witness1 = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    DisjunctiveChaumPedersenWitness witness2 = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    assertFalse(witness1.equals(witness2));
  }

  @Test
  void hashCode_equalObjects_haveSameHashCode() {
    DisjunctiveChaumPedersenWitness witness1 = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    DisjunctiveChaumPedersenWitness witness2 = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    assertEquals(witness1.hashCode(), witness2.hashCode());
  }

  @Test
  void hashCode_consistency() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 0);
    int initialHashCode = witness.hashCode();
    assertEquals(initialHashCode, witness.hashCode());
    assertEquals(initialHashCode, witness.hashCode()); // Check multiple times
  }

  @Test
  void toString_containsClassNameAndV_doesNotContainSecretR() {
    DisjunctiveChaumPedersenWitness witness = DisjunctiveChaumPedersenWitness.create(sampleR, 1);
    String witnessString = witness.toString();
    assertTrue(witnessString.contains("DisjunctiveChaumPedersenWitness"));
    assertTrue(witnessString.contains("v=1"));
    assertFalse(witnessString.contains(sampleR.toString())); // Ensure secret is not logged
    assertTrue(witnessString.contains("r=[secret]"));
  }
}
