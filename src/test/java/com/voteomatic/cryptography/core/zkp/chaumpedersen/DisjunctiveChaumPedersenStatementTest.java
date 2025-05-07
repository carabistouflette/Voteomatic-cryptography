package com.voteomatic.cryptography.core.zkp.chaumpedersen;

import static org.junit.jupiter.api.Assertions.*;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DisjunctiveChaumPedersenStatementTest {

  private PublicKey publicKey;
  private Ciphertext ciphertext;
  private BigInteger m0;
  private BigInteger m1;
  private DisjunctiveChaumPedersenStatement statement;

  // Sample values
  private final BigInteger p_val = BigInteger.valueOf(23);
  private final BigInteger g_val = BigInteger.valueOf(5);
  private final BigInteger q_val = p_val.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = 11
  private final DomainParameters domainParams = new DomainParameters(p_val, g_val, q_val);
  private final BigInteger h_val = BigInteger.valueOf(10); // y = g^x mod p (assuming some x)
  private final BigInteger c1 = BigInteger.valueOf(15); // g^r mod p
  private final BigInteger c2 = BigInteger.valueOf(20); // m*h^r mod p

  @BeforeEach
  void setUp() {
    publicKey = new PublicKey(domainParams, h_val);
    ciphertext = new Ciphertext(c1, c2);
    m0 = BigInteger.ONE; // Often g^0
    m1 = domainParams.getG(); // Often g^1
    statement = DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, m1);
  }

  @Test
  void constructor_validInputs_success() {
    assertNotNull(statement);
    assertEquals(domainParams.getP(), statement.getP());
    assertEquals(domainParams.getG(), statement.getG());
    assertEquals(domainParams.getQ(), statement.getQ()); // Check q as well
    assertEquals(domainParams, statement.getParams()); // Check params object
    assertEquals(h_val, statement.getH());
    assertEquals(c1, statement.getC1());
    assertEquals(c2, statement.getC2());
    assertEquals(m0, statement.getM0());
    assertEquals(m1, statement.getM1()); // m1 is g
  }

  @Test
  void constructor_nullPublicKey_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              DisjunctiveChaumPedersenStatement.create(null, ciphertext, m0, m1);
            });
    assertEquals("Public key cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullCiphertext_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              DisjunctiveChaumPedersenStatement.create(publicKey, null, m0, m1);
            });
    assertEquals("Ciphertext cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullM0_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, null, m1);
            });
    assertEquals("Message m0 cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullM1_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, null);
            });
    assertEquals("Message m1 cannot be null", exception.getMessage());
  }

  // Test internal null check (might be hard to trigger if PublicKey/Ciphertext validate)
  @Test
  void constructor_publicKeyWithNullComponent_throwsNullPointerException() {
    // PublicKey constructor throws NPE if p is null
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> {
              // PublicKey constructor now takes DomainParameters, so test null params
              new PublicKey(null, h_val);
            });
    // Verify the message comes from PublicKey's check.
    assertTrue(exception.getMessage().contains("DomainParameters cannot be null"));
  }

  @Test
  void constructor_ciphertextWithNullComponent_throwsIllegalArgumentException() {
    // Ciphertext constructor allows nulls, but Statement constructor checks components
    Ciphertext badCipher = new Ciphertext(null, c2); // c1 is null
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              DisjunctiveChaumPedersenStatement.create(publicKey, badCipher, m0, m1);
            });
    // Verify the message comes from Statement's check
    assertTrue(
        exception
            .getMessage()
            .contains(
                "DomainParameters, public key value (h), or ciphertext components cannot be null"));
  }

  @Test
  void getters_returnCorrectValues() {
    assertEquals(domainParams.getP(), statement.getP());
    assertEquals(domainParams.getG(), statement.getG());
    assertEquals(domainParams.getQ(), statement.getQ());
    assertEquals(domainParams, statement.getParams());
    assertEquals(h_val, statement.getH());
    assertEquals(c1, statement.getC1());
    assertEquals(c2, statement.getC2());
    assertEquals(m0, statement.getM0());
    assertEquals(m1, statement.getM1());
  }

  @Test
  void equals_sameObject_returnsTrue() {
    assertTrue(statement.equals(statement));
  }

  @Test
  void equals_nullObject_returnsFalse() {
    assertFalse(statement.equals(null));
  }

  @Test
  void equals_differentClass_returnsFalse() {
    assertFalse(statement.equals("a string"));
  }

  @Test
  void equals_equalObjects_returnsTrue() {
    DisjunctiveChaumPedersenStatement statement1 =
        DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, m1);
    DisjunctiveChaumPedersenStatement statement2 =
        DisjunctiveChaumPedersenStatement.create(
            new PublicKey(domainParams, h_val), // Use same params and h
            new Ciphertext(c1, c2),
            m0,
            m1 // m1 is g from domainParams
            );
    assertTrue(statement1.equals(statement2));
  }

  @Test
  void equals_differentP_returnsFalse() {
    DomainParameters diffParams =
        new DomainParameters(p_val.add(BigInteger.ONE), g_val, q_val); 
    PublicKey diffKey = new PublicKey(diffParams, h_val);
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(diffKey, ciphertext, m0, m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentG_returnsFalse() {
    DomainParameters diffParams =
        new DomainParameters(p_val, g_val.add(BigInteger.ONE), q_val);
    PublicKey diffKey = new PublicKey(diffParams, h_val);
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(diffKey, ciphertext, m0, m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentH_returnsFalse() {
    PublicKey diffKey = new PublicKey(domainParams, h_val.add(BigInteger.ONE));
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(diffKey, ciphertext, m0, m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentC1_returnsFalse() {
    Ciphertext diffCipher = new Ciphertext(c1.add(BigInteger.ONE), c2);
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(publicKey, diffCipher, m0, m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentC2_returnsFalse() {
    Ciphertext diffCipher = new Ciphertext(c1, c2.add(BigInteger.ONE));
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(publicKey, diffCipher, m0, m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentM0_returnsFalse() {
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0.add(BigInteger.ONE), m1);
    assertFalse(statement.equals(other));
  }

  @Test
  void equals_differentM1_returnsFalse() {
    DisjunctiveChaumPedersenStatement other =
        DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, m1.add(BigInteger.ONE));
    assertFalse(statement.equals(other));
  }

  @Test
  void hashCode_equalObjects_haveSameHashCode() {
    DisjunctiveChaumPedersenStatement statement1 =
        DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, m1);
    DisjunctiveChaumPedersenStatement statement2 =
        DisjunctiveChaumPedersenStatement.create(
            new PublicKey(domainParams, h_val),
            new Ciphertext(c1, c2),
            m0,
            m1 // m1 is g from domainParams
            );
    assertEquals(statement1.hashCode(), statement2.hashCode());
  }

  @Test
  void hashCode_consistency() {
    int initialHashCode = statement.hashCode();
    assertEquals(initialHashCode, statement.hashCode());
    assertEquals(initialHashCode, statement.hashCode()); // Check multiple times
  }

  @Test
  void toString_containsClassNameAndFieldValues() {
    String statementString = statement.toString();
    assertTrue(statementString.contains("DisjunctiveChaumPedersenStatement"));
    // Check that the params object's toString is included
    assertTrue(statementString.contains("params=" + domainParams.toString()));
    assertTrue(statementString.contains("h=" + h_val));
    assertTrue(statementString.contains("c1=" + c1));
    assertTrue(statementString.contains("c2=" + c2));
    assertTrue(statementString.contains("m0=" + m0));
    assertTrue(statementString.contains("m1=" + m1)); // m1 is g
  }
}
