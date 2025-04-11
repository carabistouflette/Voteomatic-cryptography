package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
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
class DisjunctiveChaumPedersenProverTest {

    @Mock
    private SecureRandomGenerator randomGenerator;
    @Mock
    private HashAlgorithm hashAlgorithm;

    @InjectMocks
    private DisjunctiveChaumPedersenProver prover;

    // Sample crypto parameters (use small values for easier testing)
    private final BigInteger p = BigInteger.valueOf(23);
    private final BigInteger g = BigInteger.valueOf(5);
    private final BigInteger x = BigInteger.valueOf(6); // Secret key
    private final BigInteger h = BigInteger.valueOf(8); // Public key y = g^x mod p = 5^6 mod 23 = 8
    private final BigInteger q = p.subtract(BigInteger.ONE); // Order = 22

    private PublicKey publicKey;
    private BigInteger m0; // Represents vote 0 (e.g., g^0 = 1)
    private BigInteger m1; // Represents vote 1 (e.g., g^1 = g)
    private BigInteger r; // ElGamal randomness used for ciphertext
    private Ciphertext ciphertext0; // Encrypts m0
    private Ciphertext ciphertext1; // Encrypts m1

    private DisjunctiveChaumPedersenStatement statement0;
    private DisjunctiveChaumPedersenWitness witness0;
    private DisjunctiveChaumPedersenStatement statement1;
    private DisjunctiveChaumPedersenWitness witness1;

    // Mocked random values
    private final BigInteger mockW0 = BigInteger.valueOf(3);
    private final BigInteger mockW1 = BigInteger.valueOf(4);
    private final BigInteger mockSimulatedC0 = BigInteger.valueOf(11);
    private final BigInteger mockSimulatedC1 = BigInteger.valueOf(12);
    private final BigInteger mockSimulatedR0 = BigInteger.valueOf(13);
    private final BigInteger mockSimulatedR1 = BigInteger.valueOf(14);
    private final BigInteger mockChallengeHash = BigInteger.valueOf(15); // H(...) mod q

    @BeforeEach
    void setUp() throws SecurityUtilException {
        publicKey = new PublicKey(p, g, h);
        m0 = BigInteger.ONE;
        m1 = g; // 5
        r = BigInteger.valueOf(7); // ElGamal randomness

        // Ciphertext for m0 (c1=g^r, c2=m0*h^r)
        BigInteger c1_0 = g.modPow(r, p); // 5^7 mod 23 = 17
        BigInteger c2_0 = m0.multiply(h.modPow(r, p)).mod(p); // 1 * 8^7 mod 23 = 1 * 12 mod 23 = 12
        ciphertext0 = new Ciphertext(c1_0, c2_0); // (17, 12)
        statement0 = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext0, m0, m1);
        witness0 = new DisjunctiveChaumPedersenWitness(r, 0); // Witness for encrypting m0

        // Ciphertext for m1 (c1=g^r, c2=m1*h^r)
        BigInteger c1_1 = g.modPow(r, p); // 5^7 mod 23 = 17 (same c1)
        BigInteger c2_1 = m1.multiply(h.modPow(r, p)).mod(p); // 5 * 8^7 mod 23 = 5 * 12 mod 23 = 60 mod 23 = 14
        ciphertext1 = new Ciphertext(c1_1, c2_1); // (17, 14)
        statement1 = new DisjunctiveChaumPedersenStatement(publicKey, ciphertext1, m0, m1);
        witness1 = new DisjunctiveChaumPedersenWitness(r, 1); // Witness for encrypting m1

    }


    @Test
    void constructor_nullRandomGenerator_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> new DisjunctiveChaumPedersenProver(null, hashAlgorithm));
    }

    @Test
    void constructor_nullHashAlgorithm_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> new DisjunctiveChaumPedersenProver(randomGenerator, null));
    }

    @Test
    void generateProof_invalidStatementType_throwsIllegalArgumentException() {
        Statement invalidStatement = mock(Statement.class);
        assertThrows(IllegalArgumentException.class, () -> prover.generateProof(invalidStatement, witness0));
    }

    @Test
    void generateProof_invalidWitnessType_throwsIllegalArgumentException() {
        Witness invalidWitness = mock(Witness.class);
        assertThrows(IllegalArgumentException.class, () -> prover.generateProof(statement0, invalidWitness));
    }

    @Test
    void generateProof_caseV0_success() throws ZkpException, SecurityUtilException {
        // Mock hash calculation result for this specific test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());

        // Mock random numbers needed for v=0 case
        when(randomGenerator.generateBigInteger(q))
            .thenReturn(mockSimulatedC1) // c1' (simulated challenge)
            .thenReturn(mockSimulatedR1) // r1' (simulated response)
            .thenReturn(mockW0);         // w0 (real commitment random)

        // Expected calculations
        // Simulate v=1
        BigInteger expected_g_pow_r1 = g.modPow(mockSimulatedR1, p); // 5^14 mod 23 = 6
        BigInteger expected_c1_pow_neg_c1 = ciphertext0.getC1().modPow(mockSimulatedC1.negate(), p); // 17^(-12) mod 23 = 17^10 mod 23 = 9
        BigInteger expected_a1 = expected_g_pow_r1.multiply(expected_c1_pow_neg_c1).mod(p); // 6 * 9 mod 23 = 54 mod 23 = 8

        BigInteger expected_h_pow_r1 = h.modPow(mockSimulatedR1, p); // 10^14 mod 23 = 3
        BigInteger c2_div_m1 = ciphertext0.getC2().multiply(m1.modInverse(p)).mod(p); // 16 * 5^-1 mod 23 = 16 * 14 mod 23 = 224 mod 23 = 17
        BigInteger c2_div_m1_pow_neg_c1 = c2_div_m1.modPow(mockSimulatedC1.negate(), p); // 17^(-12) mod 23 = 17^10 mod 23 = 9
        BigInteger expected_b1 = expected_h_pow_r1.multiply(c2_div_m1_pow_neg_c1).mod(p); // 6 * 9 mod 23 = 54 mod 23 = 8

        // Real proof v=0
        BigInteger expected_a0 = g.modPow(mockW0, p); // 5^3 mod 23 = 125 mod 23 = 10
        BigInteger expected_b0 = h.modPow(mockW0, p); // 8^3 mod 23 = 512 mod 23 = 6

        // Challenge c = H(...) mod q
        BigInteger expected_c = mockChallengeHash.mod(q); // 15 mod 22 = 15

        // Real challenge c0 = c - c1' mod q
        BigInteger expected_c0 = expected_c.subtract(mockSimulatedC1).mod(q); // (15 - 12) mod 22 = 3

        // Real response r0 = w0 + c0 * r mod q
        BigInteger expected_r0 = mockW0.add(expected_c0.multiply(r)).mod(q); // 3 + (3 * 7) mod 22 = 3 + 21 mod 22 = 24 mod 22 = 2

        // Execute
        Proof proof = prover.generateProof(statement0, witness0);

        // Verify
        assertTrue(proof instanceof DisjunctiveChaumPedersenProof);
        DisjunctiveChaumPedersenProof dcpProof = (DisjunctiveChaumPedersenProof) proof;

        assertEquals(expected_a0, dcpProof.getA0());
        assertEquals(expected_b0, dcpProof.getB0());
        assertEquals(expected_c0, dcpProof.getC0());
        assertEquals(expected_r0, dcpProof.getR0());
        assertEquals(expected_a1, dcpProof.getA1());
        assertEquals(expected_b1, dcpProof.getB1());
        assertEquals(mockSimulatedC1, dcpProof.getC1()); // Should be the simulated challenge
        assertEquals(mockSimulatedR1, dcpProof.getR1()); // Should be the simulated response

        // Verify hash was called once with the correct structure (byte array)
        verify(hashAlgorithm, times(1)).hash(any(byte[].class));
        // Verify random generator calls
        verify(randomGenerator, times(3)).generateBigInteger(q);
    }

     @Test
    void generateProof_caseV1_success() throws ZkpException, SecurityUtilException {
        // Mock hash calculation result for this specific test
        when(hashAlgorithm.hash(any(byte[].class))).thenReturn(mockChallengeHash.toByteArray());

        // Mock random numbers needed for v=1 case
        when(randomGenerator.generateBigInteger(q))
            .thenReturn(mockSimulatedC0) // c0' (simulated challenge)
            .thenReturn(mockSimulatedR0) // r0' (simulated response)
            .thenReturn(mockW1);         // w1 (real commitment random)

        // Expected calculations
        // Simulate v=0
        BigInteger expected_g_pow_r0 = g.modPow(mockSimulatedR0, p); // 5^13 mod 23 = 10
        BigInteger expected_c1_pow_neg_c0 = ciphertext1.getC1().modPow(mockSimulatedC0.negate(), p); // 17^(-11) mod 23 = 17^11 mod 23 = 3
        BigInteger expected_a0 = expected_g_pow_r0.multiply(expected_c1_pow_neg_c0).mod(p); // 10 * 3 mod 23 = 30 mod 23 = 7

        BigInteger expected_h_pow_r0 = h.modPow(mockSimulatedR0, p); // 10^13 mod 23 = 9
        BigInteger c2_div_m0 = ciphertext1.getC2().multiply(m0.modInverse(p)).mod(p); // 11 * 1^-1 mod 23 = 11
        BigInteger c2_div_m0_pow_neg_c0 = c2_div_m0.modPow(mockSimulatedC0.negate(), p); // 11^(-11) mod 23 = 11^11 mod 23 = 9
        BigInteger expected_b0 = expected_h_pow_r0.multiply(c2_div_m0_pow_neg_c0).mod(p); // 18 * 14 mod 23 = 252 mod 23 = 22

        // Real proof v=1
        BigInteger expected_a1 = g.modPow(mockW1, p); // 5^4 mod 23 = 625 mod 23 = 4
        BigInteger expected_b1 = h.modPow(mockW1, p); // 8^4 mod 23 = 4096 mod 23 = 2

        // Challenge c = H(...) mod q
        BigInteger expected_c = mockChallengeHash.mod(q); // 15 mod 22 = 15

        // Real challenge c1 = c - c0' mod q
        BigInteger expected_c1 = expected_c.subtract(mockSimulatedC0).mod(q); // (15 - 11) mod 22 = 4

        // Real response r1 = w1 + c1 * r mod q
        BigInteger expected_r1 = mockW1.add(expected_c1.multiply(r)).mod(q); // 4 + (4 * 7) mod 22 = 4 + 28 mod 22 = 32 mod 22 = 10

        // Execute
        Proof proof = prover.generateProof(statement1, witness1);

        // Verify
        assertTrue(proof instanceof DisjunctiveChaumPedersenProof);
        DisjunctiveChaumPedersenProof dcpProof = (DisjunctiveChaumPedersenProof) proof;

        assertEquals(expected_a0, dcpProof.getA0());
        assertEquals(expected_b0, dcpProof.getB0());
        assertEquals(mockSimulatedC0, dcpProof.getC0()); // Should be the simulated challenge
        assertEquals(mockSimulatedR0, dcpProof.getR0()); // Should be the simulated response
        assertEquals(expected_a1, dcpProof.getA1());
        assertEquals(expected_b1, dcpProof.getB1());
        assertEquals(expected_c1, dcpProof.getC1()); // Should be the real challenge
        assertEquals(expected_r1, dcpProof.getR1()); // Should be the real response

        // Verify hash was called once
        verify(hashAlgorithm, times(1)).hash(any(byte[].class));
         // Verify random generator calls
        verify(randomGenerator, times(3)).generateBigInteger(q);
    }

    @Test
    void generateProof_randomGeneratorThrowsException_throwsZkpException() throws SecurityUtilException {
        SecurityUtilException secEx = new SecurityUtilException("Random fail");
        when(randomGenerator.generateBigInteger(q)).thenThrow(secEx);

        ZkpException exception = assertThrows(ZkpException.class, () -> prover.generateProof(statement0, witness0));
        assertTrue(exception.getMessage().contains("Failed to generate Disjunctive Chaum-Pedersen proof"));
        assertEquals(secEx, exception.getCause());
    }

     @Test
    void generateProof_hashAlgorithmThrowsException_throwsZkpException() throws SecurityUtilException {
        // Mock random numbers needed to reach hash calculation
        when(randomGenerator.generateBigInteger(q))
            .thenReturn(mockSimulatedC1)
            .thenReturn(mockSimulatedR1)
            .thenReturn(mockW0);

        SecurityUtilException secEx = new SecurityUtilException("Hash fail");
        when(hashAlgorithm.hash(any(byte[].class))).thenThrow(secEx);

        ZkpException exception = assertThrows(ZkpException.class, () -> prover.generateProof(statement0, witness0));
        assertTrue(exception.getMessage().contains("Failed to generate Disjunctive Chaum-Pedersen proof"));
        assertEquals(secEx, exception.getCause());
    }

     @Test
    void generateProof_modInverseThrowsArithmeticException_throwsZkpException() throws SecurityUtilException {
         // Create a scenario where modInverse fails (e.g., m1 is 0 or not coprime to p)
         // This is unlikely with typical crypto params but good to test boundary
         BigInteger bad_m1 = p; // Not invertible mod p
         Ciphertext bad_ciphertext = new Ciphertext(ciphertext0.getC1(), ciphertext0.getC2()); // Use ciphertext0 for simplicity
         DisjunctiveChaumPedersenStatement bad_statement = new DisjunctiveChaumPedersenStatement(publicKey, bad_ciphertext, m0, bad_m1);
         DisjunctiveChaumPedersenWitness bad_witness = new DisjunctiveChaumPedersenWitness(r, 0); // v=0, so simulation for v=1 will fail

         when(randomGenerator.generateBigInteger(q))
            .thenReturn(mockSimulatedC1)
            .thenReturn(mockSimulatedR1); // Only need these for the failing simulation path

         ZkpException exception = assertThrows(ZkpException.class, () -> prover.generateProof(bad_statement, bad_witness));
         assertTrue(exception.getMessage().contains("Failed to generate Disjunctive Chaum-Pedersen proof"));
         assertTrue(exception.getCause() instanceof ArithmeticException); // Expect modInverse failure
     }
}