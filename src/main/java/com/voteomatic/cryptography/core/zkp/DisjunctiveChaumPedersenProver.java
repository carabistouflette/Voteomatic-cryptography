package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.DomainParameters; // Added
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Implements the prover logic for the Disjunctive Chaum-Pedersen ZKP scheme.
 * Generates a proof that an ElGamal ciphertext encrypts one of two known messages.
 */
public class DisjunctiveChaumPedersenProver implements ZkpProver {

    private final SecureRandomGenerator randomGenerator;
    private final HashAlgorithm hashAlgorithm;

    public DisjunctiveChaumPedersenProver(SecureRandomGenerator randomGenerator, HashAlgorithm hashAlgorithm) {
        this.randomGenerator = Objects.requireNonNull(randomGenerator, "SecureRandomGenerator cannot be null");
        this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "HashAlgorithm cannot be null");
    }

    @Override
    public Proof generateProof(Statement statement, Witness witness) throws ZkpException {
        if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
            throw new IllegalArgumentException("Statement must be an instance of DisjunctiveChaumPedersenStatement");
        }
        if (!(witness instanceof DisjunctiveChaumPedersenWitness)) {
            throw new IllegalArgumentException("Witness must be an instance of DisjunctiveChaumPedersenWitness");
        }

        DisjunctiveChaumPedersenStatement stmt = (DisjunctiveChaumPedersenStatement) statement;
        DisjunctiveChaumPedersenWitness wit = (DisjunctiveChaumPedersenWitness) witness;

        // Retrieve parameters from the statement
        DomainParameters params = stmt.getParams();
        BigInteger p = params.getP();
        BigInteger g = params.getG();
        BigInteger q = params.getQ(); // Use the correct subgroup order q
        BigInteger h = stmt.getH();
        BigInteger c1 = stmt.getC1();
        BigInteger c2 = stmt.getC2();
        BigInteger m0 = stmt.getM0();
        BigInteger m1 = stmt.getM1();
        BigInteger r = wit.getR(); // ElGamal randomness
        int v = wit.getV();       // Actual message index (0 or 1)

        // Removed incorrect calculation: q = p - 1
        // q is now correctly retrieved from DomainParameters

        try {
            BigInteger a0, b0, r0, c0, c; // Declare c here
            BigInteger a1, b1, r1, c1_challenge; // Renamed c1 to c1_challenge to avoid confusion with ciphertext c1

            if (v == 0) { // Real proof for m0, simulate for m1
                // Simulate for v=1
                // Generate random values in [0, q-1]
                c1_challenge = randomGenerator.generateBigInteger(q); // Random challenge for simulated branch
                r1 = randomGenerator.generateBigInteger(q);           // Random response for simulated branch

                // Calculate simulated commitments a1, b1
                // a1 = g^r1 * c1^(-c1_challenge) mod p
                BigInteger g_pow_r1 = g.modPow(r1, p);
                BigInteger c1_pow_neg_c1 = c1.modPow(c1_challenge.negate(), p); // c1^(-c1_challenge)
                a1 = g_pow_r1.multiply(c1_pow_neg_c1).mod(p);

                // b1 = h^r1 * (c2/m1)^(-c1_challenge) mod p
                BigInteger h_pow_r1 = h.modPow(r1, p);
                BigInteger c2_div_m1 = c2.multiply(m1.modInverse(p)).mod(p); // c2 * m1^-1
                BigInteger c2_div_m1_pow_neg_c1 = c2_div_m1.modPow(c1_challenge.negate(), p);
                b1 = h_pow_r1.multiply(c2_div_m1_pow_neg_c1).mod(p);

                // Real proof for v=0
                BigInteger w0 = randomGenerator.generateBigInteger(q); // Real random commitment value in [0, q-1]
                a0 = g.modPow(w0, p);
                b0 = h.modPow(w0, p);

                // Calculate overall challenge c = H(public values || commitments)
                c = calculateChallenge(p, g, h, stmt.getC1(), stmt.getC2(), m0, m1, a0, b0, a1, b1, q);

                // Calculate real challenge c0 = c - c1_challenge mod q
                c0 = c.subtract(c1_challenge).mod(q);

                // Calculate real response r0 = w0 + c0 * r mod q
                r0 = w0.add(c0.multiply(r)).mod(q);

            } else { // Real proof for m1, simulate for m0 (v == 1)
                // Simulate for v=0
                // Generate random values in [0, q-1]
                c0 = randomGenerator.generateBigInteger(q); // Random challenge for simulated branch
                r0 = randomGenerator.generateBigInteger(q); // Random response for simulated branch

                // Calculate simulated commitments a0, b0
                // a0 = g^r0 * c1^(-c0) mod p
                BigInteger g_pow_r0 = g.modPow(r0, p);
                BigInteger c1_pow_neg_c0 = c1.modPow(c0.negate(), p);
                a0 = g_pow_r0.multiply(c1_pow_neg_c0).mod(p);

                // b0 = h^r0 * (c2/m0)^(-c0) mod p
                BigInteger h_pow_r0 = h.modPow(r0, p);
                BigInteger c2_div_m0 = c2.multiply(m0.modInverse(p)).mod(p); // c2 * m0^-1
                BigInteger c2_div_m0_pow_neg_c0 = c2_div_m0.modPow(c0.negate(), p);
                b0 = h_pow_r0.multiply(c2_div_m0_pow_neg_c0).mod(p);

                // Real proof for v=1
                BigInteger w1 = randomGenerator.generateBigInteger(q); // Real random commitment value in [0, q-1]
                a1 = g.modPow(w1, p);
                b1 = h.modPow(w1, p);

                // Calculate overall challenge c = H(public values || commitments)
                c = calculateChallenge(p, g, h, stmt.getC1(), stmt.getC2(), m0, m1, a0, b0, a1, b1, q);

                // Calculate real challenge c1 = c - c0 mod q
                c1_challenge = c.subtract(c0).mod(q);

                // Calculate real response r1 = w1 + c1 * r mod q
                r1 = w1.add(c1_challenge.multiply(r)).mod(q);
            }

            // Return proof with individual challenges and responses
            return new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1_challenge, r1);

        } catch (SecurityUtilException | ArithmeticException e) {
            throw new ZkpException("Failed to generate Disjunctive Chaum-Pedersen proof: " + e.getMessage(), e);
        }
    }

    /**
     * Calculates the Fiat-Shamir challenge hash.
     * The hash includes all public parameters and the commitments.
     * IMPORTANT: The order and representation of hashed elements must be consistent
     * between prover and verifier.
     */
    private BigInteger calculateChallenge(BigInteger p, BigInteger g, BigInteger h,
                                          BigInteger c1, BigInteger c2, BigInteger m0, BigInteger m1,
                                          BigInteger a0, BigInteger b0, BigInteger a1, BigInteger b1,
                                          BigInteger q) throws SecurityUtilException {

        // Concatenate byte representations of all inputs. Use a fixed-size or delimited format if necessary.
        byte[] pBytes = p.toByteArray();
        byte[] gBytes = g.toByteArray();
        byte[] hBytes = h.toByteArray();
        byte[] c1Bytes = c1.toByteArray();
        byte[] c2Bytes = c2.toByteArray();
        byte[] m0Bytes = m0.toByteArray();
        byte[] m1Bytes = m1.toByteArray();
        byte[] a0Bytes = a0.toByteArray();
        byte[] b0Bytes = b0.toByteArray();
        byte[] a1Bytes = a1.toByteArray();
        byte[] b1Bytes = b1.toByteArray();

        // Simple concatenation - consider using a more robust serialization format
        int totalLength = pBytes.length + gBytes.length + hBytes.length + c1Bytes.length + c2Bytes.length +
                          m0Bytes.length + m1Bytes.length + a0Bytes.length + b0Bytes.length + a1Bytes.length + b1Bytes.length;
        byte[] inputBytes = new byte[totalLength];
        int offset = 0;
        System.arraycopy(pBytes, 0, inputBytes, offset, pBytes.length); offset += pBytes.length;
        System.arraycopy(gBytes, 0, inputBytes, offset, gBytes.length); offset += gBytes.length;
        System.arraycopy(hBytes, 0, inputBytes, offset, hBytes.length); offset += hBytes.length;
        System.arraycopy(c1Bytes, 0, inputBytes, offset, c1Bytes.length); offset += c1Bytes.length;
        System.arraycopy(c2Bytes, 0, inputBytes, offset, c2Bytes.length); offset += c2Bytes.length;
        System.arraycopy(m0Bytes, 0, inputBytes, offset, m0Bytes.length); offset += m0Bytes.length;
        System.arraycopy(m1Bytes, 0, inputBytes, offset, m1Bytes.length); offset += m1Bytes.length;
        System.arraycopy(a0Bytes, 0, inputBytes, offset, a0Bytes.length); offset += a0Bytes.length;
        System.arraycopy(b0Bytes, 0, inputBytes, offset, b0Bytes.length); offset += b0Bytes.length;
        System.arraycopy(a1Bytes, 0, inputBytes, offset, a1Bytes.length); offset += a1Bytes.length;
        System.arraycopy(b1Bytes, 0, inputBytes, offset, b1Bytes.length); //offset += b1Bytes.length; // No need to update offset after last copy

        byte[] hash = hashAlgorithm.hash(inputBytes);
        BigInteger challenge = new BigInteger(1, hash); // Ensure positive BigInteger

        // Reduce the challenge modulo q
        return challenge.mod(q);
    }
}