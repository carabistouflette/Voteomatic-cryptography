package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SchnorrProverTest {

    private HashAlgorithm mockHashAlgorithm;
    private SecureRandomGenerator mockSecureRandomGenerator;
    private SchnorrProver prover;

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger y;
    private BigInteger x;
    private SchnorrStatement statement;
    private SchnorrWitness witness;

    @BeforeEach
    void setUp() {
        mockHashAlgorithm = Mockito.mock(HashAlgorithm.class);
        mockSecureRandomGenerator = Mockito.mock(SecureRandomGenerator.class);
        prover = new SchnorrProver(mockHashAlgorithm, mockSecureRandomGenerator);

        // Standard parameters
        p = new BigInteger("23");
        q = new BigInteger("11");
        g = new BigInteger("4"); // Generator of order 11 mod 23 (4^1=4, 4^2=16, 4^3=18, 4^4=3, ...)
        x = new BigInteger("7"); // Secret
        y = g.modPow(x, p); // 4^7 mod 23 = 18

        statement = new SchnorrStatement(p, q, g, y);
        witness = new SchnorrWitness(x);
    }

    @Test
    void constructor_nullHashAlgorithm_throwsException() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrProver(null, mockSecureRandomGenerator);
        });
        assertEquals("HashAlgorithm cannot be null", e.getMessage());
    }

    @Test
    void constructor_nullRandomGenerator_throwsException() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> {
            new SchnorrProver(mockHashAlgorithm, null);
        });
        assertEquals("SecureRandomGenerator cannot be null", e.getMessage());
    }

    @Test
    void generateProof_nullStatement_throwsException() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> {
            prover.generateProof(null, witness);
        });
        assertEquals("Statement cannot be null", e.getMessage());
    }

    @Test
    void generateProof_nullWitness_throwsException() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> {
            prover.generateProof(statement, null);
        });
        assertEquals("Witness cannot be null", e.getMessage());
    }

    @Test
    void generateProof_success() throws ZkpException, SecurityUtilException {
        BigInteger v = new BigInteger("5"); // Mock random nonce
        BigInteger t = g.modPow(v, p); // 4^5 mod 23 = 16
        byte[] hashInput = "some_hash_input".getBytes(); // Placeholder, actual input is complex
        byte[] hashOutput = new BigInteger("12345").toByteArray(); // Mock hash output
        BigInteger c_hash = new BigInteger(1, hashOutput);
        BigInteger c = c_hash.mod(q); // 12345 mod 11 = 3
        BigInteger s = v.subtract(c.multiply(x)).mod(q); // (5 - 3*7) mod 11 = (5 - 21) mod 11 = -16 mod 11 = 6

        // Mock dependencies
        when(mockSecureRandomGenerator.generateBigInteger(q)).thenReturn(v);
        when(mockHashAlgorithm.hash(any(byte[].class))).thenReturn(hashOutput);

        // Execute
        SchnorrProof proof = prover.generateProof(statement, witness);

        // Verify
        assertNotNull(proof);
        assertEquals(t, proof.getT());
        assertEquals(s, proof.getS());

        // Verify mocks were called
        verify(mockSecureRandomGenerator).generateBigInteger(q);
        verify(mockHashAlgorithm).hash(any(byte[].class));
    }

    @Test
    void generateProof_randomGeneratorReturnsZeroFirst() throws ZkpException, SecurityUtilException {
        BigInteger v = new BigInteger("5"); // Mock random nonce
        BigInteger t = g.modPow(v, p);
        byte[] hashOutput = new BigInteger("12345").toByteArray();
        BigInteger c_hash = new BigInteger(1, hashOutput);
        BigInteger c = c_hash.mod(q);
        BigInteger s = v.subtract(c.multiply(x)).mod(q);

        // Mock dependencies: return 0 first, then the valid v
        when(mockSecureRandomGenerator.generateBigInteger(q))
            .thenReturn(BigInteger.ZERO) // First call returns 0
            .thenReturn(v);             // Second call returns valid v
        when(mockHashAlgorithm.hash(any(byte[].class))).thenReturn(hashOutput);

        // Execute
        SchnorrProof proof = prover.generateProof(statement, witness);

        // Verify
        assertNotNull(proof);
        assertEquals(t, proof.getT());
        assertEquals(s, proof.getS());

        // Verify mock was called twice for random generation
        verify(mockSecureRandomGenerator, times(2)).generateBigInteger(q);
        verify(mockHashAlgorithm).hash(any(byte[].class));
    }


    @Test
    void generateProof_randomGeneratorThrowsException() throws SecurityUtilException {
        // Mock random generator to throw exception
        SecurityUtilException randomException = new SecurityUtilException("Random failed");
        when(mockSecureRandomGenerator.generateBigInteger(q)).thenThrow(randomException);

        // Execute and verify exception
        ZkpException e = assertThrows(ZkpException.class, () -> {
            prover.generateProof(statement, witness);
        });
        assertEquals("Failed to generate random number for proof", e.getMessage());
        assertSame(randomException, e.getCause());
    }

    @Test
    void generateProof_hashAlgorithmThrowsException() throws SecurityUtilException {
        BigInteger v = new BigInteger("5"); // Mock random nonce

        // Mock random generator to succeed
        when(mockSecureRandomGenerator.generateBigInteger(q)).thenReturn(v);
        // Mock hash algorithm to throw exception
        SecurityUtilException hashException = new SecurityUtilException("Hash failed");
        when(mockHashAlgorithm.hash(any(byte[].class))).thenThrow(hashException);

        // Execute and verify exception
        ZkpException e = assertThrows(ZkpException.class, () -> {
            prover.generateProof(statement, witness);
        });
        // The exception message comes from the first catch block in generateProof
        // because SecurityUtilException is caught there.
        assertEquals("Failed to generate random number for proof", e.getMessage());
        assertSame(hashException, e.getCause());

        // Comment: Testing the ArithmeticException catch blocks (lines 91-92) is hard
        // with valid Schnorr parameters (p prime, q prime factor of p-1, g generator).
        // These exceptions typically arise from invalid inputs like non-positive modulus
        // which should ideally be validated earlier or are assumed correct by the protocol.

        // Comment: Testing the IOException catch block in computeChallenge (lines 127-130)
        // is not feasible as ByteArrayOutputStream does not throw IOException on write operations.
    }
}