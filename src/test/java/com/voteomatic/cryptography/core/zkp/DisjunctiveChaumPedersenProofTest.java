package com.voteomatic.cryptography.core.zkp;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DisjunctiveChaumPedersenProofTest {

  private BigInteger a0, b0, c0, r0, a1, b1, c1, r1;
  private DisjunctiveChaumPedersenProof proof;

  @BeforeEach
  void setUp() {
    a0 = BigInteger.valueOf(1);
    b0 = BigInteger.valueOf(2);
    c0 = BigInteger.valueOf(3);
    r0 = BigInteger.valueOf(4);
    a1 = BigInteger.valueOf(5);
    b1 = BigInteger.valueOf(6);
    c1 = BigInteger.valueOf(7);
    r1 = BigInteger.valueOf(8);
    proof = new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1, r1);
  }

  @Test
  void constructor_validInputs_success() {
    assertNotNull(proof);
    assertEquals(a0, proof.getA0());
    assertEquals(b0, proof.getB0());
    assertEquals(c0, proof.getC0());
    assertEquals(r0, proof.getR0());
    assertEquals(a1, proof.getA1());
    assertEquals(b1, proof.getB1());
    assertEquals(c1, proof.getC1());
    assertEquals(r1, proof.getR1());
  }

  @Test
  void constructor_nullInputs_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(null, b0, c0, r0, a1, b1, c1, r1),
        "a0 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, null, c0, r0, a1, b1, c1, r1),
        "b0 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, null, r0, a1, b1, c1, r1),
        "c0 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, c0, null, a1, b1, c1, r1),
        "r0 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, null, b1, c1, r1),
        "a1 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, null, c1, r1),
        "b1 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, null, r1),
        "c1 cannot be null");
    assertThrows(
        NullPointerException.class,
        () -> new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1, null),
        "r1 cannot be null");
  }

  @Test
  void getters_returnCorrectValues() {
    assertEquals(a0, proof.getA0());
    assertEquals(b0, proof.getB0());
    assertEquals(c0, proof.getC0());
    assertEquals(r0, proof.getR0());
    assertEquals(a1, proof.getA1());
    assertEquals(b1, proof.getB1());
    assertEquals(c1, proof.getC1());
    assertEquals(r1, proof.getR1());
  }

  @Test
  void equals_sameObject_returnsTrue() {
    assertTrue(proof.equals(proof));
  }

  @Test
  void equals_nullObject_returnsFalse() {
    assertFalse(proof.equals(null));
  }

  @Test
  void equals_differentClass_returnsFalse() {
    assertFalse(proof.equals("a string"));
  }

  @Test
  void equals_equalObjects_returnsTrue() {
    DisjunctiveChaumPedersenProof proof1 =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1, r1);
    DisjunctiveChaumPedersenProof proof2 =
        new DisjunctiveChaumPedersenProof(
            BigInteger.valueOf(1),
            BigInteger.valueOf(2),
            BigInteger.valueOf(3),
            BigInteger.valueOf(4),
            BigInteger.valueOf(5),
            BigInteger.valueOf(6),
            BigInteger.valueOf(7),
            BigInteger.valueOf(8));
    assertTrue(proof1.equals(proof2));
  }

  @Test
  void equals_differentA0_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0.add(BigInteger.ONE), b0, c0, r0, a1, b1, c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentB0_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0.add(BigInteger.ONE), c0, r0, a1, b1, c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentC0_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0.add(BigInteger.ONE), r0, a1, b1, c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentR0_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0.add(BigInteger.ONE), a1, b1, c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentA1_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1.add(BigInteger.ONE), b1, c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentB1_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1.add(BigInteger.ONE), c1, r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentC1_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1.add(BigInteger.ONE), r1);
    assertFalse(proof.equals(other));
  }

  @Test
  void equals_differentR1_returnsFalse() {
    DisjunctiveChaumPedersenProof other =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1, r1.add(BigInteger.ONE));
    assertFalse(proof.equals(other));
  }

  @Test
  void hashCode_equalObjects_haveSameHashCode() {
    DisjunctiveChaumPedersenProof proof1 =
        new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1, r1);
    DisjunctiveChaumPedersenProof proof2 =
        new DisjunctiveChaumPedersenProof(
            BigInteger.valueOf(1),
            BigInteger.valueOf(2),
            BigInteger.valueOf(3),
            BigInteger.valueOf(4),
            BigInteger.valueOf(5),
            BigInteger.valueOf(6),
            BigInteger.valueOf(7),
            BigInteger.valueOf(8));
    assertEquals(proof1.hashCode(), proof2.hashCode());
  }

  @Test
  void hashCode_consistency() {
    int initialHashCode = proof.hashCode();
    assertEquals(initialHashCode, proof.hashCode());
    assertEquals(initialHashCode, proof.hashCode());
  }

  @Test
  void toString_containsClassNameAndFieldValues() {
    String proofString = proof.toString();
    assertTrue(proofString.contains("DisjunctiveChaumPedersenProof"));
    assertTrue(proofString.contains("a0=" + a0));
    assertTrue(proofString.contains("b0=" + b0));
    assertTrue(proofString.contains("c0=" + c0));
    assertTrue(proofString.contains("r0=" + r0));
    assertTrue(proofString.contains("a1=" + a1));
    assertTrue(proofString.contains("b1=" + b1));
    assertTrue(proofString.contains("c1=" + c1));
    assertTrue(proofString.contains("r1=" + r1));
  }
}
