package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DisjunctiveChaumPedersenVerifierTest {

    @Mock
    private HashAlgorithm hashAlgorithm;

    @InjectMocks
    private DisjunctiveChaumPedersenVerifier verifier;

    // Consistent crypto parameters from ProverTest
    private final BigInteger p = BigInteger.valueOf(23);
    private final BigInteger g = BigInteger.valueOf(5);
    private final BigInteger h = BigInteger.valueOf(8); // y = g^x mod p = 5^6 mod 23 = 8
    private final BigInteger q = p.subtract(BigInteger.ONE); // Order = 22

    private PublicKey publicKey;
    private BigInteger m0;
    private BigInteger m1;
    private Ciphertext ciphertext; // Use ciphertext0 from prover test
    private DisjunctiveChaumPedersenStatement statement;

    // Valid proof components corresponding to v=0 case from ProverTest (Recalculated with h=8)
    private final BigInteger a0_valid = BigInteger.valueOf(10); // g^w0
    private final BigInteger b0_valid = BigInteger.valueOf(6);  // h^w0 = 8^3 = 6
    private final BigInteger c0_valid = BigInteger.valueOf(3);  // c - c1'
    private final BigInteger r0_valid = BigInteger.valueOf(2);  // w0 + c0*r
    private final BigInteger a1_valid = BigInteger.valueOf(6);  // Adjusted to make check1_eq1 pass: g^r1 = 13, c1^c1 = 6 -> a1 = 13*6^-1 = 13*4 = 52 = 6
    private final BigInteger b1_valid = BigInteger.valueOf(9);  // Simulated b1 = h^r1*(c2/m1)^(-c1) = 8^14*(12*14)^(-12) = 6*7^(-12) = 6*13=78=9
    private final BigInteger c1_valid = BigInteger.valueOf(12); // Simulated c1'
    private final BigInteger r1_valid = BigInteger.valueOf(14); // Simulated r1'

    private DisjunctiveChaumPedersenProof validProof;

    // Mocked hash result corresponding to the valid proof components
    private final BigInteger mockChallengeHash = BigInteger.valueOf(15); // H(...) mod q = 15

    @BeforeEach
    void setUp() throws SecurityUtilException {
        publicKey = new PublicKey(p, g, h);
        m0 = BigInteger.ONE;
        m1 = g; // 5
        // Use ciphertext corresponding to m0 encryption (Recalculated with h=8)
        BigInteger c1_val = BigInteger.valueOf(17); // g^r (r=7)
        BigInteger c2_val = BigInteger.valueOf(12); // m0*h^r = 1 * 8^7 = 12
        ciphertext = new Ciphertext(c1_val, c2_val); // (17, 12)
        statement = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, m0, m1);

        validProof = new DisjunctiveChaumPedersenProof(a0_valid, b0_valid, c0_valid, r0_valid, a1_valid, b1_valid, c1_valid, r1_valid);
    }

    @Test
    void constructor_nullHashAlgorithm_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> new DisjunctiveChaumPedersenVerifier(null));
    }

    @Test
    void verifyProof_invalidStatementType_throwsIllegalArgumentException() {
        Statement invalidStatement = mock(Statement.class);
        assertThrows(IllegalArgumentException.class, () -> verifier.verifyProof(invalidStatement, validProof));
    }

    @Test
    void verifyProof_invalidProofType_throwsIllegalArgumentException() {
        Proof invalidProof = mock(Proof.class);
        assertThrows(IllegalArgumentException.class, () -> verifier.verifyProof(statement, invalidProof));
    }

    @Test
    void verifyProof_validProof_returnsTrue() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        assertTrue(verifier.verifyProof(statement, validProof));
        // Verify hash was called once
        verify(hashAlgorithm, times(1)).hash(any(byte[].class));
    }

    @Test
    void verifyProof_challengeCheckFails_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test (verifier needs it to compare challenges)
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        // Tamper with c0 so c0 + c1 != calculated_c
        DisjunctiveChaumPedersenProof badProof = new DisjunctiveChaumPedersenProof(
            a0_valid, b0_valid, c0_valid.add(BigInteger.ONE), r0_valid, // Bad c0
            a1_valid, b1_valid, c1_valid, r1_valid
        );
        assertFalse(verifier.verifyProof(statement, badProof));
        // Hash should still be calculated once
        verify(hashAlgorithm, times(1)).hash(any(byte[].class));
    }

     @Test
    void verifyProof_check0Eq1Fails_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        // Tamper with a0 so g^r0 != a0 * c1^c0
         DisjunctiveChaumPedersenProof badProof = new DisjunctiveChaumPedersenProof(
            a0_valid.add(BigInteger.ONE), b0_valid, c0_valid, r0_valid, // Bad a0
            a1_valid, b1_valid, c1_valid, r1_valid
        );
        assertFalse(verifier.verifyProof(statement, badProof));
    }

     @Test
    void verifyProof_check0Eq2Fails_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        // Tamper with b0 so h^r0 != b0 * (c2/m0)^c0
         DisjunctiveChaumPedersenProof badProof = new DisjunctiveChaumPedersenProof(
            a0_valid, b0_valid.add(BigInteger.ONE), c0_valid, r0_valid, // Bad b0
            a1_valid, b1_valid, c1_valid, r1_valid
        );
        assertFalse(verifier.verifyProof(statement, badProof));
    }

     @Test
    void verifyProof_check1Eq1Fails_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        // Tamper with a1 so g^r1 != a1 * c1^c1
         DisjunctiveChaumPedersenProof badProof = new DisjunctiveChaumPedersenProof(
            a0_valid, b0_valid, c0_valid, r0_valid,
            a1_valid.add(BigInteger.ONE), b1_valid, c1_valid, r1_valid // Bad a1
        );
        assertFalse(verifier.verifyProof(statement, badProof));
    }

     @Test
    void verifyProof_check1Eq2Fails_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
        // Tamper with b1 so h^r1 != b1 * (c2/m1)^c1
         DisjunctiveChaumPedersenProof badProof = new DisjunctiveChaumPedersenProof(
            a0_valid, b0_valid, c0_valid, r0_valid,
            a1_valid, b1_valid.add(BigInteger.ONE), c1_valid, r1_valid // Bad b1
        );
        assertFalse(verifier.verifyProof(statement, badProof));
    }

    @Test
    void verifyProof_hashAlgorithmThrowsException_returnsFalse() throws SecurityUtilException, ZkpException {
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
    void verifyProof_modInverseThrowsArithmeticException_returnsFalse() throws ZkpException, SecurityUtilException {
        // Mock hash calculation for this test (needed before modInverse is called)
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
         // Create a statement where m0 is not invertible mod p
         BigInteger bad_m0 = p;
         DisjunctiveChaumPedersenStatement badStatement = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext, bad_m0, m1);

         // The current implementation catches ArithmeticException and returns false
         assertFalse(verifier.verifyProof(badStatement, validProof));
     }

     @Test
    void calculateChallenge_matchesProverLogic() throws Exception {
        // Mock hash calculation for this test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());
         // This test is implicitly covered by the successful verification test,
         // but we can explicitly call the private method using reflection if needed
         // for more isolated testing (though generally testing via public API is preferred).

         // We rely on the fact that if verifyProof passes with mocked hash,
         // the internal calculateChallenge must be producing the expected input
         // for the mocked hash function.
         assertTrue(verifier.verifyProof(statement, validProof)); // Re-run for clarity
         verify(hashAlgorithm, times(1)).hash(any(byte[].class)); // Confirms challenge calculation happened
    }
}