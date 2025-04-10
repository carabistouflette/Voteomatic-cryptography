package com.voteomatic.cryptography.voting;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class VoteTest {

    @Test
    void constructorAndGetter_ValidInput_ShouldSucceed() {
        String option = "CandidateA";
        Vote vote = new Vote(option);
        assertEquals(option, vote.getSelectedOption(), "getSelectedOption should return the value passed to the constructor.");
    }


    @Test
    void equals_SameObject_ShouldReturnTrue() {
        Vote vote1 = new Vote("OptionX");
        assertTrue(vote1.equals(vote1), "An object should be equal to itself.");
    }

    @Test
    void equals_EqualObjects_ShouldReturnTrue() {
        String option = "OptionY";
        Vote vote1 = new Vote(option);
        Vote vote2 = new Vote(option); // Same value
        assertTrue(vote1.equals(vote2), "Objects with the same selectedOption should be equal.");
    }

    @Test
    void equals_DifferentObjects_ShouldReturnFalse() {
        Vote vote1 = new Vote("OptionA");
        Vote vote2 = new Vote("OptionB"); // Different value
        assertFalse(vote1.equals(vote2), "Objects with different selectedOption should not be equal.");
    }

    @Test
    void equals_NullObject_ShouldReturnFalse() {
        Vote vote1 = new Vote("OptionZ");
        assertFalse(vote1.equals(null), "An object should not be equal to null.");
    }

    @Test
    void equals_DifferentType_ShouldReturnFalse() {
        Vote vote1 = new Vote("OptionW");
        Object other = new Object();
        assertFalse(vote1.equals(other), "An object should not be equal to an object of a different type.");
    }

    @Test
    void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
        String option = "OptionP";
        Vote vote1 = new Vote(option);
        Vote vote2 = new Vote(option); // Same value
        assertEquals(vote1.hashCode(), vote2.hashCode(), "Equal objects should have equal hash codes.");
    }

    @Test
    void hashCode_DifferentObjects_ShouldHaveDifferentHashCodes() {
        // While collisions are possible, they should generally differ for different strings.
        Vote vote1 = new Vote("OptionQ");
        Vote vote2 = new Vote("OptionR"); // Different value
        assertNotEquals(vote1.hashCode(), vote2.hashCode(), "Hash codes for different objects should ideally differ.");
    }

    @Test
    void toString_ContainsRedactedValue() {
        String option = "SecretCandidate";
        Vote vote = new Vote(option);
        String str = vote.toString();

        assertTrue(str.contains("selectedOption='[REDACTED]'"), "toString should contain '[REDACTED]' for the option.");
        assertFalse(str.contains(option), "toString should NOT contain the actual selected option.");
        assertTrue(str.startsWith("Vote{"), "toString should start with the class name.");
        assertTrue(str.endsWith("}"), "toString should end with '}'.");
    }
}