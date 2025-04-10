package com.voteomatic.cryptography.core.zkp;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class SchnorrStatementTest {

    private final BigInteger p = new BigInteger("23");
    private final BigInteger q = new BigInteger("11");
    private final BigInteger g = new BigInteger("4");
    private final BigInteger y = new BigInteger("9"); // Example public key y = g^x mod p

    @Test
    void constructorAndGetters() {
        SchnorrStatement statement = new SchnorrStatement(p, q, g, y);
        assertEquals(p, statement.getP());
        assertEquals(q, statement.getQ());
        assertEquals(g, statement.getG());
        assertEquals(y, statement.getY());
    }

    @Test
    void constructor_nullP_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrStatement(null, q, g, y);
        });
        assertEquals("Statement parameters cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullQ_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrStatement(p, null, g, y);
        });
        assertEquals("Statement parameters cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullG_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrStatement(p, q, null, y);
        });
        assertEquals("Statement parameters cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullY_throwsException() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrStatement(p, q, g, null);
        });
        assertEquals("Statement parameters cannot be null", exception.getMessage());
    }


    @Test
    void equalsAndHashCode() {
        SchnorrStatement statement1 = new SchnorrStatement(p, q, g, y);
        SchnorrStatement statement2 = new SchnorrStatement(p, q, g, y);
        SchnorrStatement statement3 = new SchnorrStatement(p, q, g, BigInteger.TEN); // Different y
        SchnorrStatement statement4 = new SchnorrStatement(p, q, BigInteger.ONE, y); // Different g
        SchnorrStatement statement5 = new SchnorrStatement(p, BigInteger.ONE, g, y); // Different q
        SchnorrStatement statement6 = new SchnorrStatement(BigInteger.ONE, q, g, y); // Different p

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
        SchnorrStatement statement = new SchnorrStatement(p, q, g, y);
        String expectedString = "SchnorrStatement{p=23, q=11, g=4, y=9}";
        assertEquals(expectedString, statement.toString());
    }
}