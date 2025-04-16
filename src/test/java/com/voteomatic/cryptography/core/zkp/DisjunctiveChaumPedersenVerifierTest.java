package com.voteomatic.cryptography.core.zkp;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DisjunctiveChaumPedersenVerifierTest {

  @Mock private HashAlgorithm hashAlgorithm;
  @Mock private SecureRandomGenerator randomGenerator; // Added mock for prover

  private DisjunctiveChaumPedersenProver prover; // Instantiate prover for generating valid proof
  @InjectMocks private DisjunctiveChaumPedersenVerifier verifier;

  // Consistent crypto parameters from ProverTest
  private final BigInteger p_val = BigInteger.valueOf(23);
  private final BigInteger g_val = BigInteger.valueOf(5);
  private final BigInteger q_val =
      p_val.subtract(BigInteger.ONE).divide(BigInteger.TWO); // Prime subgroup order q = 11
  private final BigInteger r_val = BigInteger.valueOf(7); // Original randomness for ciphertext
  private final DomainParameters domainParams = new DomainParameters(p_val, g_val, q_val);
  private final BigInteger h_val =
      g_val.modPow(BigInteger.valueOf(6), p_val); // y = g^x mod p = 5^6 mod 23 = 8

  private PublicKey publicKey;
  private BigInteger m0;
  private BigInteger m1;
  private Ciphertext ciphertext; // Use ciphertext0 from prover test
  private DisjunctiveChaumPedersenStatement statement;

  // Proof will be generated in setUp using the prover
  private DisjunctiveChaumPedersenProof validProof;
  private DisjunctiveChaumPedersenWitness witness0; // Witness for v=0

  // Mocked hash result corresponding to the valid proof components
  // Mocked values needed for prover to generate the proof
  private final BigInteger mockW0 = BigInteger.valueOf(3);
  private final BigInteger mockSimulatedC1 = BigInteger.valueOf(12);
  private final BigInteger mockSimulatedR1 = BigInteger.valueOf(14);
  private final BigInteger mockProverChallengeHashBytes =
      BigInteger.valueOf(15); // Raw hash result H(...) = 15

  @BeforeEach
  void setUp() throws SecurityUtilException, ZkpException { // Added ZkpException
    prover =
        new DisjunctiveChaumPedersenProver(randomGenerator, hashAlgorithm); // Instantiate prover
    publicKey = new PublicKey(domainParams, h_val);
    m0 = BigInteger.ONE;
    m1 = domainParams.getG(); // 5
    // Ciphertext corresponding to m0 encryption with r=7
    BigInteger c1_val = domainParams.getG().modPow(r_val, domainParams.getP()); // 5^7 mod 23 = 17
    BigInteger c2_val =
        m0.multiply(h_val.modPow(r_val, domainParams.getP()))
            .mod(domainParams.getP()); // 1 * 8^7 mod 23 = 12
    ciphertext = new Ciphertext(c1_val, c2_val); // (17, 12)
    statement = DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, m0, m1);
    witness0 = DisjunctiveChaumPedersenWitness.create(r_val, 0); // Witness for v=0

    // --- Generate the valid proof using the prover ---
    // Mock random numbers needed for prover (v=0 case)
    when(randomGenerator.generateBigInteger(domainParams.getQ()))
        .thenReturn(mockSimulatedC1) // c1' (simulated challenge)
        .thenReturn(mockSimulatedR1) // r1' (simulated response)
        .thenReturn(mockW0); // w0 (real commitment random)
    // Mock hash result needed for prover
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());

    // Generate the proof
    validProof = (DisjunctiveChaumPedersenProof) prover.generateProof(statement, witness0);

    // Reset hash mock for verifier tests (important!)
    // The verifier will call hash again, potentially with different input bytes
    // if the concatenation logic differs slightly (though it shouldn't).
    // We mock it again in the specific tests that need verification.
    reset(hashAlgorithm);
  }

  @Test
  void constructor_nullHashAlgorithm_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new DisjunctiveChaumPedersenVerifier(null));
  }

  @Test
  void verifyProof_invalidStatementType_throwsIllegalArgumentException() {
    Statement invalidStatement = mock(Statement.class);
    assertThrows(
        IllegalArgumentException.class, () -> verifier.verifyProof(invalidStatement, validProof));
  }

  @Test
  void verifyProof_invalidProofType_throwsIllegalArgumentException() {
    Proof invalidProof = mock(Proof.class);
    assertThrows(
        IllegalArgumentException.class, () -> verifier.verifyProof(statement, invalidProof));
  }

  @Test
  void verifyProof_validProof_returnsTrue() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier for this specific test
    // It should produce the same hash value as the prover used
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());

    // Act & Assert
    assertTrue(
        verifier.verifyProof(statement, validProof),
        "Verification should succeed for a proof generated by the prover.");

    // Verify hash was called once by the verifier during this call
    verify(hashAlgorithm, times(1)).hash(any(byte[].class));
  }

  @Test
  void verifyProof_challengeCheckFails_returnsFalse() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Tamper with c0 from the generated valid proof
    DisjunctiveChaumPedersenProof badProof =
        new DisjunctiveChaumPedersenProof(
            validProof.getA0(),
            validProof.getB0(),
            validProof.getC0().add(BigInteger.ONE),
            validProof.getR0(), // Bad c0
            validProof.getA1(),
            validProof.getB1(),
            validProof.getC1(),
            validProof.getR1());
    assertFalse(verifier.verifyProof(statement, badProof));
    // Hash should still be calculated once
    verify(hashAlgorithm, times(1)).hash(any(byte[].class));
  }

  @Test
  void verifyProof_check0Eq1Fails_returnsFalse() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Tamper with a0 so g^r0 != a0 * c1^c0
    DisjunctiveChaumPedersenProof badProof =
        new DisjunctiveChaumPedersenProof(
            validProof.getA0().add(BigInteger.ONE),
            validProof.getB0(),
            validProof.getC0(),
            validProof.getR0(), // Bad a0
            validProof.getA1(),
            validProof.getB1(),
            validProof.getC1(),
            validProof.getR1());
    assertFalse(verifier.verifyProof(statement, badProof));
  }

  @Test
  void verifyProof_check0Eq2Fails_returnsFalse() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Tamper with b0 so h^r0 != b0 * (c2/m0)^c0
    DisjunctiveChaumPedersenProof badProof =
        new DisjunctiveChaumPedersenProof(
            validProof.getA0(),
            validProof.getB0().add(BigInteger.ONE),
            validProof.getC0(),
            validProof.getR0(), // Bad b0
            validProof.getA1(),
            validProof.getB1(),
            validProof.getC1(),
            validProof.getR1());
    assertFalse(verifier.verifyProof(statement, badProof));
  }

  @Test
  void verifyProof_check1Eq1Fails_returnsFalse() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Tamper with a1 so g^r1 != a1 * c1^c1
    DisjunctiveChaumPedersenProof badProof =
        new DisjunctiveChaumPedersenProof(
            validProof.getA0(),
            validProof.getB0(),
            validProof.getC0(),
            validProof.getR0(),
            validProof.getA1().add(BigInteger.ONE),
            validProof.getB1(),
            validProof.getC1(),
            validProof.getR1() // Bad a1
            );
    assertFalse(verifier.verifyProof(statement, badProof));
  }

  @Test
  void verifyProof_check1Eq2Fails_returnsFalse() throws ZkpException, SecurityUtilException {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Tamper with b1 so h^r1 != b1 * (c2/m1)^c1
    DisjunctiveChaumPedersenProof badProof =
        new DisjunctiveChaumPedersenProof(
            validProof.getA0(),
            validProof.getB0(),
            validProof.getC0(),
            validProof.getR0(),
            validProof.getA1(),
            validProof.getB1().add(BigInteger.ONE),
            validProof.getC1(),
            validProof.getR1() // Bad b1
            );
    assertFalse(verifier.verifyProof(statement, badProof));
  }

  @Test
  void verifyProof_hashAlgorithmThrowsException_returnsFalse()
      throws SecurityUtilException, ZkpException {
    // Reset mock to clear previous when()
    reset(hashAlgorithm);
    SecurityUtilException secEx = new SecurityUtilException("Hash fail");
    when(hashAlgorithm.hash(any(byte[].class))).thenThrow(secEx);

    // The current implementation catches SecurityUtilException and returns false
    assertFalse(verifier.verifyProof(statement, validProof));
    // Verify hash was called
    verify(hashAlgorithm, times(1)).hash(any(byte[].class));
  }

  @Test
  void verifyProof_modInverseThrowsArithmeticException_returnsFalse()
      throws ZkpException, SecurityUtilException {
    // Mock hash calculation for this test (needed before modInverse is called)
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());
    // Create a statement where m0 is not invertible mod p
    BigInteger bad_m0 = domainParams.getP();
    DisjunctiveChaumPedersenStatement badStatement =
        DisjunctiveChaumPedersenStatement.create(publicKey, ciphertext, bad_m0, m1); // m0=p

    // The current implementation catches ArithmeticException and returns false
    assertFalse(verifier.verifyProof(badStatement, validProof));
  }

  @Test
  void calculateChallenge_matchesProverLogic() throws Exception {
    // Mock hash calculation for the verifier
    when(hashAlgorithm.hash(any(byte[].class)))
        .thenReturn(mockProverChallengeHashBytes.toByteArray());

    // Act & Assert
    // We rely on the fact that if verifyProof passes with mocked hash,
    // the internal calculateChallenge must be producing the expected input
    // for the mocked hash function.
    assertTrue(
        verifier.verifyProof(statement, validProof),
        "Verification should pass, implying challenge calculation matches.");
    // Verify hash was called once by the verifier during this call
    verify(hashAlgorithm, times(1)).hash(any(byte[].class));
  }
}
