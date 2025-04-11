package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Implements the verifier logic for the Disjunctive Chaum-Pedersen ZKP scheme.
 * Verifies a proof that an ElGamal ciphertext encrypts one of two known messages.
 */
public class DisjunctiveChaumPedersenVerifier implements ZkpVerifier {

    private final HashAlgorithm hashAlgorithm;

    public DisjunctiveChaumPedersenVerifier(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "HashAlgorithm cannot be null");
    }

    @Override
    public boolean verifyProof(Statement statement, Proof proof) throws ZkpException {
        if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
            throw new IllegalArgumentException("Statement must be an instance of DisjunctiveChaumPedersenStatement");
        }
        if (!(proof instanceof DisjunctiveChaumPedersenProof)) {
            throw new IllegalArgumentException("Proof must be an instance of DisjunctiveChaumPedersenProof");
        }

        DisjunctiveChaumPedersenStatement stmt = (DisjunctiveChaumPedersenStatement) statement;
        DisjunctiveChaumPedersenProof prf = (DisjunctiveChaumPedersenProof) proof;

        BigInteger p = stmt.getP();
        BigInteger g = stmt.getG();
        BigInteger h = stmt.getH();
        BigInteger c1 = stmt.getC1(); // g^r
        BigInteger c2 = stmt.getC2(); // m*h^r
        BigInteger m0 = stmt.getM0();
        BigInteger m1 = stmt.getM1();

        BigInteger a0 = prf.getA0();
        BigInteger b0 = prf.getB0();
        BigInteger c0 = prf.getC0();
        BigInteger r0 = prf.getR0();
        BigInteger a1 = prf.getA1();
        BigInteger b1 = prf.getB1();
        BigInteger c1_challenge = prf.getC1(); // Renamed from c1 to avoid clash
        BigInteger r1 = prf.getR1();

        // Use p-1 as the order q for simplicity. Match the prover.
        BigInteger q = p.subtract(BigInteger.ONE);

        try {
            // 1. Recalculate the overall challenge c' = H(public values || commitments)
            BigInteger calculated_c = calculateChallenge(p, g, h, c1, c2, m0, m1, a0, b0, a1, b1, q);

            // 2. Check if c' == c0 + c1 (mod q)
            boolean challengeCheck = calculated_c.equals(c0.add(c1_challenge).mod(q));
            if (!challengeCheck) {
                // System.err.println("Challenge check failed: calculated_c=" + calculated_c + ", c0+c1=" + c0.add(c1_challenge).mod(q));
                return false;
            }

            // 3. Verify first equation for v=0: g^r0 == a0 * c1^c0 (mod p)
            BigInteger g_pow_r0 = g.modPow(r0, p);
            BigInteger c1_pow_c0 = c1.modPow(c0, p);
            BigInteger check0_lhs = a0.multiply(c1_pow_c0).mod(p);
            boolean check0_eq1 = g_pow_r0.equals(check0_lhs);
            if (!check0_eq1) {
                 // System.err.println("Check 0 Eq 1 failed: g^r0=" + g_pow_r0 + ", a0*c1^c0=" + check0_lhs);
                 return false;
            }


            // 4. Verify second equation for v=0: h^r0 == b0 * (c2/m0)^c0 (mod p)
            BigInteger h_pow_r0 = h.modPow(r0, p);
            BigInteger c2_div_m0 = c2.multiply(m0.modInverse(p)).mod(p);
            BigInteger c2_div_m0_pow_c0 = c2_div_m0.modPow(c0, p);
            BigInteger check0_rhs = b0.multiply(c2_div_m0_pow_c0).mod(p);
            boolean check0_eq2 = h_pow_r0.equals(check0_rhs);
             if (!check0_eq2) {
                 // System.err.println("Check 0 Eq 2 failed: h^r0=" + h_pow_r0 + ", b0*(c2/m0)^c0=" + check0_rhs);
                 return false;
             }

            // 5. Verify first equation for v=1: g^r1 == a1 * c1^c1 (mod p)
            BigInteger g_pow_r1 = g.modPow(r1, p);
            BigInteger c1_pow_c1 = c1.modPow(c1_challenge, p);
            BigInteger check1_lhs = a1.multiply(c1_pow_c1).mod(p);
            boolean check1_eq1 = g_pow_r1.equals(check1_lhs);
             if (!check1_eq1) {
                 // System.err.println("Check 1 Eq 1 failed: g^r1=" + g_pow_r1 + ", a1*c1^c1=" + check1_lhs);
                 return false;
             }

            // 6. Verify second equation for v=1: h^r1 == b1 * (c2/m1)^c1 (mod p)
            BigInteger h_pow_r1 = h.modPow(r1, p);
            BigInteger c2_div_m1 = c2.multiply(m1.modInverse(p)).mod(p);
            BigInteger c2_div_m1_pow_c1 = c2_div_m1.modPow(c1_challenge, p);
            BigInteger check1_rhs = b1.multiply(c2_div_m1_pow_c1).mod(p);
            boolean check1_eq2 = h_pow_r1.equals(check1_rhs);
             if (!check1_eq2) {
                 // System.err.println("Check 1 Eq 2 failed: h^r1=" + h_pow_r1 + ", b1*(c2/m1)^c1=" + check1_rhs);
                 return false;
             }

            // If all checks pass, the proof is valid
            return true;

        } catch (SecurityUtilException | ArithmeticException e) {
            // Treat calculation errors during verification as proof failure
            // Log the error for debugging if necessary
            // System.err.println("Error during verification: " + e.getMessage());
            return false;
            // Or rethrow as ZkpException if that's preferred behavior
            // throw new ZkpException("Verification failed due to calculation error: " + e.getMessage(), e);
        }
    }

    /**
     * Calculates the Fiat-Shamir challenge hash.
     * MUST match the implementation in the Prover exactly.
     */
    private BigInteger calculateChallenge(BigInteger p, BigInteger g, BigInteger h,
                                          BigInteger c1, BigInteger c2, BigInteger m0, BigInteger m1,
                                          BigInteger a0, BigInteger b0, BigInteger a1, BigInteger b1,
                                          BigInteger q) throws SecurityUtilException {
        // Concatenate byte representations - MUST match prover's implementation
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
        System.arraycopy(b1Bytes, 0, inputBytes, offset, b1Bytes.length);

        byte[] hash = hashAlgorithm.hash(inputBytes);
        BigInteger challenge = new BigInteger(1, hash); // Ensure positive

        return challenge.mod(q); // Reduce modulo q
    }
}