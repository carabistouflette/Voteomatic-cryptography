package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.securityutils.HashAlgorithm; // Ensure this import is present
import com.voteomatic.cryptography.securityutils.SecurityUtilException; // Ensure this import is present

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Implements the Verifier side of Schnorr's protocol.
 * Verifies a proof of knowledge of x for a given statement y = g^x mod p.
 */
public class SchnorrVerifier implements ZkpVerifier<SchnorrStatement, SchnorrProof> {

    private final HashAlgorithm hashAlgorithm;

    /**
     * Constructs a SchnorrVerifier.
     *
     * @param hashAlgorithm The hash algorithm used to generate the challenge.
     *                      Must be the same instance/type as used by the prover.
     * @throws IllegalArgumentException if hashAlgorithm is null.
     */
    public SchnorrVerifier(HashAlgorithm hashAlgorithm) {
        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("HashAlgorithm cannot be null");
        }
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Verifies a Schnorr proof.
     *
     * @param statement The public statement (p, q, g, y).
     * @param proof     The proof (t, s) to verify.
     * @return true if the proof is valid, false otherwise.
     * @throws IllegalArgumentException if statement or proof is null.
     * @throws ZkpException             if an error occurs during verification (e.g., hashing).
     */
    @Override
    public boolean verifyProof(SchnorrStatement statement, SchnorrProof proof) throws ZkpException {
        if (statement == null) {
            throw new IllegalArgumentException("Statement cannot be null");
        }
        if (proof == null) {
            throw new IllegalArgumentException("Proof cannot be null");
        }

        BigInteger p = statement.getP();
        BigInteger q = statement.getQ(); // q is needed for challenge computation if included in hash
        BigInteger g = statement.getG();
        BigInteger y = statement.getY();
        BigInteger t = proof.getT();
        BigInteger s = proof.getS();

        // Basic validation: Check if t and s are within expected ranges (optional but good practice)
        // e.g., t should be in [1, p-1], s should be in [0, q-1]
        if (t.compareTo(BigInteger.ONE) < 0 || t.compareTo(p) >= 0) {
             return false; // t must be in the group Z_p^*
        }
         if (s.compareTo(BigInteger.ZERO) < 0 || s.compareTo(q) >= 0) {
             return false; // s must be in Z_q
         }


        try {
            // 1. Re-compute challenge c = H(p || q || g || y || t)
            BigInteger c = computeChallenge(p, q, g, y, t);

            // 2. Compute check1 = g^s mod p
            BigInteger check1 = g.modPow(s, p);

            // 3. Compute check2 = y^c mod p
            BigInteger check2 = y.modPow(c, p);

            // 4. Compute t' = (check1 * check2) mod p
            BigInteger t_prime = check1.multiply(check2).mod(p);

            // 5. Compare t' with the commitment t from the proof
            return t_prime.equals(t);

        } catch (SecurityUtilException e) {
            throw new ZkpException("Failed to compute challenge hash during verification", e);
        } catch (ArithmeticException e) {
            // This might happen if, e.g., p is not prime or g is not a generator,
            // leading to unexpected results in modPow.
            throw new ZkpException("Arithmetic error during proof verification", e);
        }
    }

    /**
     * Computes the challenge c = H(p || q || g || y || t).
     * Must be identical to the prover's challenge computation.
     */
    private BigInteger computeChallenge(BigInteger p, BigInteger q, BigInteger g, BigInteger y, BigInteger t) throws SecurityUtilException {
        // Simple concatenation of string representations. Ensure consistent encoding.
        String dataToHash = p.toString() + "|" + q.toString() + "|" + g.toString() + "|" + y.toString() + "|" + t.toString();
        byte[] hashBytes = hashAlgorithm.hash(dataToHash.getBytes(StandardCharsets.UTF_8));
        // Convert hash bytes to a positive BigInteger
        return new BigInteger(1, hashBytes);
    }
}