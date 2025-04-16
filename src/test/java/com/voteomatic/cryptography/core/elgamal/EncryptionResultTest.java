package com.voteomatic.cryptography.core.elgamal;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EncryptionResultTest {

  private Ciphertext mockCiphertext;
  private BigInteger randomness;
  private EncryptionResult encryptionResult;

  @BeforeEach
  void setUp() {
    mockCiphertext =
        new Ciphertext(BigInteger.valueOf(123), BigInteger.valueOf(456)); // Use concrete instance
    randomness = BigInteger.valueOf(789);
    encryptionResult = new EncryptionResult(mockCiphertext, randomness);
  }

  @Test
  void constructor_validInputs_success() {
    assertNotNull(encryptionResult);
    assertEquals(mockCiphertext, encryptionResult.getCiphertext());
    assertEquals(randomness, encryptionResult.getRandomness());
  }

  @Test
  void constructor_nullCiphertext_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              new EncryptionResult(null, randomness);
            });
    assertEquals("Ciphertext cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullRandomness_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              new EncryptionResult(mockCiphertext, null);
            });
    assertEquals("Randomness cannot be null", exception.getMessage());
  }

  @Test
  void getCiphertext_returnsCorrectCiphertext() {
    assertEquals(mockCiphertext, encryptionResult.getCiphertext());
  }

  @Test
  void getRandomness_returnsCorrectRandomness() {
    assertEquals(randomness, encryptionResult.getRandomness());
  }

  @Test
  void equals_sameObject_returnsTrue() {
    assertTrue(encryptionResult.equals(encryptionResult));
  }

  @Test
  void equals_nullObject_returnsFalse() {
    assertFalse(encryptionResult.equals(null));
  }

  @Test
  void equals_differentClass_returnsFalse() {
    assertFalse(encryptionResult.equals("a string"));
  }

  @Test
  void equals_equalObjects_returnsTrue() {
    EncryptionResult otherResult =
        new EncryptionResult(
            new Ciphertext(BigInteger.valueOf(123), BigInteger.valueOf(456)),
            BigInteger.valueOf(789));
    assertTrue(encryptionResult.equals(otherResult));
  }

  @Test
  void equals_differentCiphertext_returnsFalse() {
    EncryptionResult otherResult =
        new EncryptionResult(
            new Ciphertext(BigInteger.ONE, BigInteger.TWO), // Different ciphertext
            randomness);
    assertFalse(encryptionResult.equals(otherResult));
  }

  @Test
  void equals_differentRandomness_returnsFalse() {
    EncryptionResult otherResult =
        new EncryptionResult(
            mockCiphertext, BigInteger.TEN // Different randomness
            );
    assertFalse(encryptionResult.equals(otherResult));
  }

  @Test
  void hashCode_equalObjects_haveSameHashCode() {
    EncryptionResult otherResult =
        new EncryptionResult(
            new Ciphertext(BigInteger.valueOf(123), BigInteger.valueOf(456)),
            BigInteger.valueOf(789));
    assertEquals(encryptionResult.hashCode(), otherResult.hashCode());
  }

  @Test
  void hashCode_consistency() {
    int initialHashCode = encryptionResult.hashCode();
    assertEquals(initialHashCode, encryptionResult.hashCode());
    assertEquals(initialHashCode, encryptionResult.hashCode()); // Check multiple times
  }

  @Test
  void toString_containsClassNameAndFieldValues() {
    String resultString = encryptionResult.toString();
    assertTrue(resultString.contains("EncryptionResult"));
    assertTrue(resultString.contains("ciphertext=" + mockCiphertext.toString()));
    assertTrue(resultString.contains("randomness=" + randomness.toString()));
  }
}
