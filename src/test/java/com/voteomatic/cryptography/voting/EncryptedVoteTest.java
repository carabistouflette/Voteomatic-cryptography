package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.zkp.Proof;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class EncryptedVoteTest {

    // Dummy Proof implementation for testing
    private static class DummyProof implements Proof {
        private final int id;
        public DummyProof(int id) { this.id = id; }
        @Override public boolean equals(Object o) { if (this == o) return true; if (o == null || getClass() != o.getClass()) return false; DummyProof that = (DummyProof) o; return id == that.id; }
        @Override public int hashCode() { return Integer.hashCode(id); }
    }

    private Ciphertext ciphertext1;
    private Ciphertext ciphertext2; // Different ciphertext
    private Proof proof1;
    private Proof proof2; // Different proof

    @BeforeEach
    void setUp() {
        ciphertext1 = new Ciphertext(BigInteger.ONE, BigInteger.TEN);
        ciphertext2 = new Ciphertext(BigInteger.TWO, BigInteger.valueOf(20));
        proof1 = new DummyProof(1);
        proof2 = new DummyProof(2);
    }

    @Test
    void constructorWithProof_ValidInput_ShouldSucceed() {
        EncryptedVote vote = new EncryptedVote(ciphertext1, proof1);
        assertEquals(ciphertext1, vote.getVoteCiphertext());
        assertEquals(Optional.of(proof1), vote.getValidityProof());
    }

    @Test
    void constructorWithProof_NullCiphertext_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new EncryptedVote(null, proof1),
                     "Constructor should throw NullPointerException if ciphertext is null.");
    }

    @Test
    void constructorWithProof_NullProof_ShouldSucceed() {
        EncryptedVote vote = new EncryptedVote(ciphertext1, null);
        assertEquals(ciphertext1, vote.getVoteCiphertext());
        assertEquals(Optional.empty(), vote.getValidityProof(), "Proof should be absent if null is passed.");
    }

    @Test
    void constructorWithoutProof_ValidInput_ShouldSucceed() {
        EncryptedVote vote = new EncryptedVote(ciphertext1);
        assertEquals(ciphertext1, vote.getVoteCiphertext());
        assertEquals(Optional.empty(), vote.getValidityProof(), "Proof should be absent when using the constructor without proof.");
    }

    @Test
    void constructorWithoutProof_NullCiphertext_ShouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> new EncryptedVote(null),
                     "Constructor without proof should throw NullPointerException if ciphertext is null.");
    }

    @Test
    void getVoteCiphertext_ShouldReturnCorrectCiphertext() {
        EncryptedVote vote = new EncryptedVote(ciphertext1, proof1);
        assertEquals(ciphertext1, vote.getVoteCiphertext());
    }

    @Test
    void getValidityProof_WhenProofPresent_ShouldReturnOptionalWithProof() {
        EncryptedVote vote = new EncryptedVote(ciphertext1, proof1);
        Optional<Proof> optionalProof = vote.getValidityProof();
        assertTrue(optionalProof.isPresent(), "Optional should be present when proof is provided.");
        assertEquals(proof1, optionalProof.get(), "Optional should contain the correct proof.");
    }

    @Test
    void getValidityProof_WhenProofAbsent_ShouldReturnEmptyOptional() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1); // Using constructor without proof

        assertFalse(vote1.getValidityProof().isPresent(), "Optional should be empty when proof is null.");
        assertFalse(vote2.getValidityProof().isPresent(), "Optional should be empty when using constructor without proof.");
    }

    @Test
    void equals_SameObject_ShouldReturnTrue() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        assertTrue(vote1.equals(vote1));
    }

    @Test
    void equals_EqualObjects_WithProof_ShouldReturnTrue() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, proof1); // Same values
        assertTrue(vote1.equals(vote2));
    }

    @Test
    void equals_EqualObjects_WithoutProof_ShouldReturnTrue() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1); // Same values
        assertTrue(vote1.equals(vote2));
    }

     @Test
    void equals_EqualObjects_WithNullProof_ShouldReturnTrue() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, null); // Same values
        assertTrue(vote1.equals(vote2));
    }

    @Test
    void equals_DifferentCiphertext_ShouldReturnFalse() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext2, proof1); // Different ciphertext
        assertFalse(vote1.equals(vote2));
    }

    @Test
    void equals_DifferentProof_NonNull_ShouldReturnFalse() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, proof2); // Different proof
        assertFalse(vote1.equals(vote2));
    }

    @Test
    void equals_DifferentProof_NullVsNonNull_ShouldReturnFalse() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, null); // Null proof
        EncryptedVote vote3 = new EncryptedVote(ciphertext1);      // No proof via constructor
        assertFalse(vote1.equals(vote2));
        assertFalse(vote2.equals(vote1));
        assertFalse(vote1.equals(vote3));
        assertFalse(vote3.equals(vote1));
    }

     @Test
    void equals_DifferentProof_NullVsNoProofConstructor_ShouldReturnTrue() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null); // Null proof
        EncryptedVote vote2 = new EncryptedVote(ciphertext1);      // No proof via constructor
        assertTrue(vote1.equals(vote2), "Null proof should be equal to proof omitted via constructor.");
        assertTrue(vote2.equals(vote1), "Proof omitted via constructor should be equal to null proof.");
    }


    @Test
    void equals_NullObject_ShouldReturnFalse() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        assertFalse(vote1.equals(null));
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        Object other = new Object();
        assertFalse(vote1.equals(other));
    }

    @Test
    void hashCode_EqualObjects_WithProof_ShouldHaveEqualHashCodes() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, proof1);
        assertEquals(vote1.hashCode(), vote2.hashCode());
    }

    @Test
    void hashCode_EqualObjects_WithoutProof_ShouldHaveEqualHashCodes() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1);
        assertEquals(vote1.hashCode(), vote2.hashCode());
    }

    @Test
    void hashCode_EqualObjects_WithNullProof_ShouldHaveEqualHashCodes() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1, null);
        assertEquals(vote1.hashCode(), vote2.hashCode());
    }

     @Test
    void hashCode_EqualObjects_NullProofVsNoProofConstructor_ShouldHaveEqualHashCodes() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1);
        assertEquals(vote1.hashCode(), vote2.hashCode(), "Hashcodes for null proof and omitted proof should be equal.");
    }


    @Test
    void hashCode_DifferentObjects_HashCodesMayDiffer() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, proof1);
        EncryptedVote vote2 = new EncryptedVote(ciphertext2, proof1); // Diff ciphertext
        EncryptedVote vote3 = new EncryptedVote(ciphertext1, proof2); // Diff proof
        EncryptedVote vote4 = new EncryptedVote(ciphertext1, null);   // Null proof

        assertNotEquals(vote1.hashCode(), vote2.hashCode());
        assertNotEquals(vote1.hashCode(), vote3.hashCode());
        assertNotEquals(vote1.hashCode(), vote4.hashCode());
    }

    @Test
    void toString_WithProof_ContainsProofPresent() {
        EncryptedVote vote = new EncryptedVote(ciphertext1, proof1);
        String str = vote.toString();
        assertTrue(str.contains(ciphertext1.toString()), "toString should contain ciphertext string.");
        assertTrue(str.contains("validityProof=present"), "toString should indicate proof is present.");
        assertTrue(str.startsWith("EncryptedVote{"));
        assertTrue(str.endsWith("}"));
    }

    @Test
    void toString_WithoutProof_ContainsProofAbsent() {
        EncryptedVote vote1 = new EncryptedVote(ciphertext1, null);
        EncryptedVote vote2 = new EncryptedVote(ciphertext1);
        String str1 = vote1.toString();
        String str2 = vote2.toString();

        assertTrue(str1.contains(ciphertext1.toString()));
        assertTrue(str1.contains("validityProof=absent"), "toString should indicate proof is absent when null.");
        assertTrue(str1.startsWith("EncryptedVote{"));
        assertTrue(str1.endsWith("}"));

        assertTrue(str2.contains(ciphertext1.toString()));
        assertTrue(str2.contains("validityProof=absent"), "toString should indicate proof is absent when omitted.");
        assertTrue(str2.startsWith("EncryptedVote{"));
        assertTrue(str2.endsWith("}"));
    }
}