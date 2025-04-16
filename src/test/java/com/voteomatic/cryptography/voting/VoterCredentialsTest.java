package com.voteomatic.cryptography.voting;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class VoterCredentialsTest {

  @Test
  void constructorAndGetter_ValidInput_ShouldSucceed() {
    String voterId = "voter123";
    VoterCredentials credentials = new VoterCredentials(voterId);
    assertEquals(
        voterId,
        credentials.getVoterId(),
        "getVoterId should return the value passed to the constructor.");
  }

  @Test
  void constructor_NullInput_ShouldThrowNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new VoterCredentials(null),
        "Constructor should throw NullPointerException if voterId is null.");
  }

  @Test
  void equals_SameObject_ShouldReturnTrue() {
    VoterCredentials creds1 = new VoterCredentials("id-abc");
    assertTrue(creds1.equals(creds1), "An object should be equal to itself.");
  }

  @Test
  void equals_EqualObjects_ShouldReturnTrue() {
    String voterId = "id-def";
    VoterCredentials creds1 = new VoterCredentials(voterId);
    VoterCredentials creds2 = new VoterCredentials(voterId); // Same value
    assertTrue(creds1.equals(creds2), "Objects with the same voterId should be equal.");
  }

  @Test
  void equals_DifferentObjects_ShouldReturnFalse() {
    VoterCredentials creds1 = new VoterCredentials("id-1");
    VoterCredentials creds2 = new VoterCredentials("id-2"); // Different value
    assertFalse(creds1.equals(creds2), "Objects with different voterId should not be equal.");
  }

  @Test
  void equals_NullObject_ShouldReturnFalse() {
    VoterCredentials creds1 = new VoterCredentials("id-xyz");
    assertFalse(creds1.equals(null), "An object should not be equal to null.");
  }

  @Test
  void equals_DifferentType_ShouldReturnFalse() {
    VoterCredentials creds1 = new VoterCredentials("id-pqr");
    Object other = new Object();
    assertFalse(
        creds1.equals(other), "An object should not be equal to an object of a different type.");
  }

  @Test
  void hashCode_EqualObjects_ShouldHaveEqualHashCodes() {
    String voterId = "id-hash";
    VoterCredentials creds1 = new VoterCredentials(voterId);
    VoterCredentials creds2 = new VoterCredentials(voterId); // Same value
    assertEquals(
        creds1.hashCode(), creds2.hashCode(), "Equal objects should have equal hash codes.");
  }

  @Test
  void hashCode_DifferentObjects_ShouldHaveDifferentHashCodes() {
    // While collisions are possible, they should generally differ for different strings.
    VoterCredentials creds1 = new VoterCredentials("id-hash-1");
    VoterCredentials creds2 = new VoterCredentials("id-hash-2"); // Different value
    assertNotEquals(
        creds1.hashCode(),
        creds2.hashCode(),
        "Hash codes for different objects should ideally differ.");
  }

  @Test
  void toString_ContainsFieldValue() {
    String voterId = "voter-test-id";
    VoterCredentials credentials = new VoterCredentials(voterId);
    String str = credentials.toString();

    assertTrue(
        str.contains("voterId='" + voterId + "'"),
        "toString should contain the voterId field and value.");
    assertTrue(str.startsWith("VoterCredentials{"), "toString should start with the class name.");
    assertTrue(str.endsWith("}"), "toString should end with '}'.");
  }
}
