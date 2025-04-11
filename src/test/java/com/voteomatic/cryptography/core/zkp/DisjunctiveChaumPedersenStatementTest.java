package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class DisjunctiveChaumPedersenStatementTest {

    private PublicKey publicKey;
    private Ciphertext ciphertext;
    private BigInteger m0;
    private BigInteger m1;
    private DisjunctiveChaumPedersenStatement statement;

    // Sample values (replace with realistic crypto parameters if needed for specific tests)
    private final BigInteger p = BigInteger.valueOf(23);
    private final BigInteger g = BigInteger.valueOf(5);
    private final BigInteger h = BigInteger.valueOf(10); // y = g^x mod p
    private final BigInteger c1 = BigInteger.valueOf(15); // g^r mod p
    private final BigInteger c2 = BigInteger.valueOf(20); // m*h^r mod p

    @BeforeEach
    void setUp() {
        publicKey = new PublicKey(p, g, h);
        ciphertext = new Ciphertext(c1, c2);
        m0 = BigInteger.ONE; // Often g^0
        m1 = g;             // Often g^1
        statement = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, m1);
    }

    @Test
    void constructor_validInputs_success() {
        assertNotNull(statement);
        assertEquals(p, statement.getP());
        assertEquals(g, statement.getG());
        assertEquals(h, statement.getH());
        assertEquals(c1, statement.getC1());
        assertEquals(c2, statement.getC2());
        assertEquals(m0, statement.getM0());
        assertEquals(m1, statement.getM1());
    }

    @Test
    void constructor_nullPublicKey_throwsNullPointerException() {
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
            new DisjunctiveChaumPedersenStatement(null, ciphertext, m0, m1);
        });
        assertEquals("Public key cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullCiphertext_throwsNullPointerException() {
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
            new DisjunctiveChaumPedersenStatement(publicKey, null, m0, m1);
        });
        assertEquals("Ciphertext cannot be null", exception.getMessage());
    }

    @Test
    void constructor_nullM0_throwsNullPointerException() {
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
            new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, null, m1);
        });
        assertEquals("Message m0 cannot be null", exception.getMessage());
    }

     @Test
    void constructor_nullM1_throwsNullPointerException() {
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
            new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, null);
        });
        assertEquals("Message m1 cannot be null", exception.getMessage());
    }

    // Test internal null check (might be hard to trigger if PublicKey/Ciphertext validate)
    @Test
    void constructor_publicKeyWithNullComponent_throwsNullPointerException() {
        // PublicKey constructor throws NPE if p is null
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
             new PublicKey(null, g, h); // p is null
        });
        // We don't even reach the Statement constructor in this case.
        // Verify the message comes from PublicKey's check.
        assertTrue(exception.getMessage().contains("Prime modulus p cannot be null"));
    }

     @Test
    void constructor_ciphertextWithNullComponent_throwsIllegalArgumentException() {
        // Ciphertext constructor allows nulls, but Statement constructor checks components
        Ciphertext badCipher = new Ciphertext(null, c2); // c1 is null
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
           new DisjunctiveChaumPedersenStatement(publicKey, badCipher, m0, m1);
        });
        // Verify the message comes from Statement's check
        assertTrue(exception.getMessage().contains("Public key or ciphertext components cannot be null"));
    }


    @Test
    void getters_returnCorrectValues() {
        assertEquals(p, statement.getP());
        assertEquals(g, statement.getG());
        assertEquals(h, statement.getH());
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
        DisjunctiveChaumPedersenStatement statement1 = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, m1);
        DisjunctiveChaumPedersenStatement statement2 = new DisjunctiveChaumPedersenStatement(
            new PublicKey(p, g, h),
            new Ciphertext(c1, c2),
            m0,
            m1
        );
        assertTrue(statement1.equals(statement2));
    }

    @Test
    void equals_differentP_returnsFalse() {
        PublicKey diffKey = new PublicKey(p.add(BigInteger.ONE), g, h);
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(diffKey, ciphertext, m0, m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentG_returnsFalse() {
        PublicKey diffKey = new PublicKey(p, g.add(BigInteger.ONE), h);
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(diffKey, ciphertext, m0, m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentH_returnsFalse() {
        PublicKey diffKey = new PublicKey(p, g, h.add(BigInteger.ONE));
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(diffKey, ciphertext, m0, m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentC1_returnsFalse() {
        Ciphertext diffCipher = new Ciphertext(c1.add(BigInteger.ONE), c2);
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(publicKey, diffCipher, m0, m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentC2_returnsFalse() {
        Ciphertext diffCipher = new Ciphertext(c1, c2.add(BigInteger.ONE));
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(publicKey, diffCipher, m0, m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentM0_returnsFalse() {
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0.add(BigInteger.ONE), m1);
        assertFalse(statement.equals(other));
    }

     @Test
    void equals_differentM1_returnsFalse() {
        DisjunctiveChaumPedersenStatement other = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, m1.add(BigInteger.ONE));
        assertFalse(statement.equals(other));
    }


    @Test
    void hashCode_equalObjects_haveSameHashCode() {
         DisjunctiveChaumPedersenStatement statement1 = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, m1);
         DisjunctiveChaumPedersenStatement statement2 = new DisjunctiveChaumPedersenStatement(
            new PublicKey(p, g, h),
            new Ciphertext(c1, c2),
            m0,
            m1
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
        assertTrue(statementString.contains("p=" + p));
        assertTrue(statementString.contains("g=" + g));
        assertTrue(statementString.contains("h=" + h));
        assertTrue(statementString.contains("c1=" + c1));
        assertTrue(statementString.contains("c2=" + c2));
        assertTrue(statementString.contains("m0=" + m0));
        assertTrue(statementString.contains("m1=" + m1));
    }
}