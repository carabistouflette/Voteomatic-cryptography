package com.voteomatic.cryptography.keymanagement;

import static org.junit.jupiter.api.Assertions.*;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeyPairTest {

  private PublicKey publicKey1;
  private PrivateKey privateKey1;
  private PublicKey publicKey2; // Different public key
  private PrivateKey privateKey2; // Different private key
  private KeyPair keyPair1;

  @BeforeEach
  void setUp() {
    BigInteger p1_val = new BigInteger("23");
    BigInteger g1_val = new BigInteger("5");
    BigInteger q1_val = p1_val.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = 11
    DomainParameters params1 = new DomainParameters(p1_val, g1_val, q1_val);
    BigInteger x1_val = new BigInteger("6");
    BigInteger y1_val = g1_val.modPow(x1_val, p1_val); // 8

    BigInteger p2_val = new BigInteger("29"); // Different params
    BigInteger g2_val = new BigInteger("2");
    BigInteger q2_val =
        p2_val
            .subtract(BigInteger.ONE)
            .divide(BigInteger.TWO); // q = 14 (Note: 29 is not safe prime, but q=(p-1)/2 is used)
    DomainParameters params2 = new DomainParameters(p2_val, g2_val, q2_val);
    BigInteger x2_val = new BigInteger("7");
    BigInteger y2_val = g2_val.modPow(x2_val, p2_val); // 12

    publicKey1 = new PublicKey(params1, y1_val);
    privateKey1 = new PrivateKey(params1, x1_val);
    publicKey2 = new PublicKey(params2, y2_val); // Different key
    privateKey2 = new PrivateKey(params2, x2_val); // Different key

    keyPair1 = new KeyPair(publicKey1, privateKey1);
  }

  @Test
  void constructorAndGetters_ValidInput_ShouldSucceed() {
    assertEquals(
        publicKey1,
        keyPair1.getPublicKey(),
        "getPublicKey should return the public key passed to the constructor.");
    assertEquals(
        privateKey1,
        keyPair1.getPrivateKey(),
        "getPrivateKey should return the private key passed to the constructor.");
  }

  @Test
  void constructor_NullPublicKey_ShouldThrowNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new KeyPair(null, privateKey1),
        "Constructor should throw NullPointerException if publicKey is null.");
  }

  @Test
  void constructor_NullPrivateKey_ShouldThrowNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new KeyPair(publicKey1, null),
        "Constructor should throw NullPointerException if privateKey is null.");
  }

  @Test
  void equals_SameObject_ShouldReturnTrue() {
    assertTrue(keyPair1.equals(keyPair1), "An object should be equal to itself.");
  }

  @Test
  void equals_EqualObjects_ShouldReturnTrue() {
    KeyPair keyPair2 = new KeyPair(publicKey1, privateKey1); // Same keys
    assertTrue(
        keyPair1.equals(keyPair2),
        "KeyPairs with the same public and private keys should be equal.");
  }

  @Test
  void equals_DifferentPublicKey_ShouldReturnFalse() {
    KeyPair keyPair2 = new KeyPair(publicKey2, privateKey1); // Different public key
    assertFalse(
        keyPair1.equals(keyPair2), "KeyPairs with different public keys should not be equal.");
  }

  @Test
  void equals_DifferentPrivateKey_ShouldReturnFalse() {
    KeyPair keyPair2 = new KeyPair(publicKey1, privateKey2); // Different private key
    assertFalse(
        keyPair1.equals(keyPair2), "KeyPairs with different private keys should not be equal.");
  }

  @Test
  void equals_DifferentBothKeys_ShouldReturnFalse() {
    KeyPair keyPair2 = new KeyPair(publicKey2, privateKey2); // Different keys
    assertFalse(
        keyPair1.equals(keyPair2),
        "KeyPairs with different public and private keys should not be equal.");
  }

  @Test
  void equals_NullObject_ShouldReturnFalse() {
    assertFalse(keyPair1.equals(null), "An object should not be equal to null.");
  }

  @Test
  void equals_DifferentType_ShouldReturnFalse() {
    Object other = new Object();
    assertFalse(
        keyPair1.equals(other), "An object should not be equal to an object of a different type.");
  }

  @Test
  void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
    KeyPair keyPair2 = new KeyPair(publicKey1, privateKey1); // Same keys
    assertEquals(
        keyPair1.hashCode(), keyPair2.hashCode(), "Equal objects should have equal hash codes.");
  }

  @Test
  void hashCode_DifferentObjects_HashCodesMayDiffer() {
    KeyPair keyPair2 = new KeyPair(publicKey2, privateKey1); // Different public key
    KeyPair keyPair3 = new KeyPair(publicKey1, privateKey2); // Different private key

    assertNotEquals(
        keyPair1.hashCode(),
        keyPair2.hashCode(),
        "Hash code should likely differ if public key differs.");
    assertNotEquals(
        keyPair1.hashCode(),
        keyPair3.hashCode(),
        "Hash code should likely differ if private key differs.");
  }
}
