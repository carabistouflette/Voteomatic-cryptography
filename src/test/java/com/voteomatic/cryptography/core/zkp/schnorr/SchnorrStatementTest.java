package com.voteomatic.cryptography.core.zkp.schnorr;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class SchnorrStatementTest {

  private final BigInteger p = new BigInteger("23");
  private final BigInteger q = new BigInteger("11");
  private final BigInteger g = new BigInteger("4");
  private final BigInteger y = new BigInteger("9"); // Example public key y = g^x mod p

  @Test
  void constructorAndGetters() {
    SchnorrStatement statement = SchnorrStatement.create(p, q, g, y);
    assertEquals(p, statement.getP());
    assertEquals(q, statement.getQ());
    assertEquals(g, statement.getG());
    assertEquals(y, statement.getY());
  }

  @Test
  void constructor_nullP_throwsException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrStatement.create(null, q, g, y);
            });
    assertEquals("Statement parameter primeModulus cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullQ_throwsException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrStatement.create(p, null, g, y);
            });
    assertEquals("Statement parameter subgroupOrder cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullG_throwsException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrStatement.create(p, q, null, y);
            });
    assertEquals("Statement parameter generator cannot be null", exception.getMessage());
  }

  @Test
  void constructor_nullY_throwsException() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrStatement.create(p, q, g, null);
            });
    assertEquals("Statement parameter publicValue cannot be null", exception.getMessage());
  }

  @Test
  void equalsAndHashCode() {
    SchnorrStatement statement1 = SchnorrStatement.create(p, q, g, y);
    SchnorrStatement statement2 = SchnorrStatement.create(p, q, g, y);
    SchnorrStatement statement3 = SchnorrStatement.create(p, q, g, BigInteger.TEN); // Different y
    SchnorrStatement statement4 = SchnorrStatement.create(p, q, BigInteger.ONE, y); // Different g
    SchnorrStatement statement5 = SchnorrStatement.create(p, BigInteger.ONE, g, y); // Different q
    SchnorrStatement statement6 = SchnorrStatement.create(BigInteger.ONE, q, g, y); // Different p

    // Reflexive
    assertEquals(statement1, statement1);
    assertEquals(statement1.hashCode(), statement1.hashCode());

    // Symmetric
    assertEquals(statement1, statement2);
    assertEquals(statement2, statement1);
    assertEquals(statement1.hashCode(), statement2.hashCode());

    // Transitive (implicit via statement1 <-> statement2)

    // Consistent
    assertEquals(statement1, statement2);
    assertEquals(statement1.hashCode(), statement2.hashCode());

    // Not equal to null
    assertNotEquals(null, statement1);

    // Not equal to different types
    assertNotEquals("a string", statement1);

    // Not equal with different values
    assertNotEquals(statement1, statement3);
    assertNotEquals(statement1.hashCode(), statement3.hashCode()); // Hash codes likely different
    assertNotEquals(statement1, statement4);
    assertNotEquals(statement1.hashCode(), statement4.hashCode());
    assertNotEquals(statement1, statement5);
    assertNotEquals(statement1.hashCode(), statement5.hashCode());
    assertNotEquals(statement1, statement6);
    assertNotEquals(statement1.hashCode(), statement6.hashCode());
  }

  @Test
  void testToString() {
    SchnorrStatement statement = SchnorrStatement.create(p, q, g, y);
    String expectedString =
        "SchnorrStatement{primeModulus=23, subgroupOrder=11, generator=4, publicValue=9}";
    assertEquals(expectedString, statement.toString());
  }
}
