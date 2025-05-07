package com.voteomatic.cryptography.core.zkp.schnorr;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class SchnorrVerifierTest {

  private HashAlgorithm mockHashAlgorithm;
  private SchnorrVerifier verifier;

  private BigInteger p;
  private BigInteger q;
  private BigInteger g;
  private BigInteger y;
  private SchnorrStatement statement;
  private SchnorrProof validProof; // A structurally valid proof (t, s values)

  @BeforeEach
  void setUp() {
    mockHashAlgorithm = Mockito.mock(HashAlgorithm.class);
    verifier = SchnorrVerifier.create(mockHashAlgorithm);

    // Standard parameters
    p = new BigInteger("23");
    q = new BigInteger("11");
    g = new BigInteger("4"); // Generator of order 11 mod 23
    y = new BigInteger("18"); // y = g^x mod p for some x

    statement = SchnorrStatement.create(p, q, g, y);
    // Create a proof with values assumed to be in the correct range for some tests
    validProof = SchnorrProof.create(new BigInteger("16"), new BigInteger("6"));
  }

  @Test
  void constructor_nullHashAlgorithm_throwsException() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              SchnorrVerifier.create(null);
            });
    assertEquals("HashAlgorithm cannot be null", e.getMessage());
  }

  @Test
  void verifyProof_nullStatement_throwsException() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              verifier.verifyProof(null, validProof);
            });
    assertEquals("Statement cannot be null", e.getMessage());
  }

  @Test
  void verifyProof_nullProof_throwsException() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              verifier.verifyProof(statement, null);
            });
    assertEquals("Proof cannot be null", e.getMessage());
  }

  @Test
  void verifyProof_tIsZero_returnsFalse() throws ZkpException {
    SchnorrProof proofWithZeroT = SchnorrProof.create(BigInteger.ZERO, validProof.getS());
    assertFalse(verifier.verifyProof(statement, proofWithZeroT));
  }

  @Test
  void verifyProof_tEqualsP_returnsFalse() throws ZkpException {
    SchnorrProof proofWithTequalsP = SchnorrProof.create(p, validProof.getS());
    assertFalse(verifier.verifyProof(statement, proofWithTequalsP));
  }

  @Test
  void verifyProof_tGreaterThanP_returnsFalse() throws ZkpException {
    SchnorrProof proofWithTgreaterP = SchnorrProof.create(p.add(BigInteger.ONE), validProof.getS());
    assertFalse(verifier.verifyProof(statement, proofWithTgreaterP));
  }

  @Test
  void verifyProof_sIsNegative_returnsFalse() throws ZkpException {
    SchnorrProof proofWithNegativeS =
        SchnorrProof.create(validProof.getT(), BigInteger.valueOf(-1));
    assertFalse(verifier.verifyProof(statement, proofWithNegativeS));
  }

  @Test
  void verifyProof_sEqualsQ_returnsFalse() throws ZkpException {
    SchnorrProof proofWithSequalsQ = SchnorrProof.create(validProof.getT(), q);
    assertFalse(verifier.verifyProof(statement, proofWithSequalsQ));
  }

  @Test
  void verifyProof_sGreaterThanQ_returnsFalse() throws ZkpException {
    SchnorrProof proofWithSgreaterQ = SchnorrProof.create(validProof.getT(), q.add(BigInteger.ONE));
    assertFalse(verifier.verifyProof(statement, proofWithSgreaterQ));
  }

  @Test
  void verifyProof_hashAlgorithmThrowsException() throws SecurityUtilException {
    // Mock hash algorithm to throw exception
    SecurityUtilException hashException = new SecurityUtilException("Hash failed");
    when(mockHashAlgorithm.hash(any(byte[].class))).thenThrow(hashException);

    // Execute and verify exception
    ZkpException e =
        assertThrows(
            ZkpException.class,
            () -> {
              verifier.verifyProof(statement, validProof);
            });
    assertEquals("Failed to compute challenge hash during verification", e.getMessage());
    assertSame(hashException, e.getCause());

    // Comment: Testing the ArithmeticException catch block (lines 86-90) is hard
    // with valid Schnorr parameters. It might occur with invalid parameters (e.g., p not prime)
    // causing modPow to fail, but parameter validation is typically outside the scope
    // of the verifier itself.

    // Comment: Testing the IOException catch block in computeChallenge (lines 122-125)
    // is not feasible as ByteArrayOutputStream does not throw IOException on write operations.
  }

  // Note: The successful verification path and invalid proof (wrong t/s leading to failed check)
  // are covered adequately in SchnorrProtocolTest.java.
}
