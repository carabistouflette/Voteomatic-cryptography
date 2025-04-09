package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Implements the Prover side of Schnorr's protocol for proving knowledge of a discrete logarithm.
 * Proves knowledge of x such that y = g^x mod p.
 */
public class SchnorrProver implements ZkpProver<SchnorrStatement, SchnorrWitness, SchnorrProof> {

    private final HashAlgorithm hashAlgorithm;
    private final SecureRandomGenerator secureRandomGenerator;

    /**
     * Constructs a SchnorrProver.
     *
     * @param hashAlgorithm         The hash algorithm to use for generating the challenge.
     * @param secureRandomGenerator The secure random generator for generating the secret nonce 'v'.
     * @throws IllegalArgumentException if any dependency is null.
     */
    public SchnorrProver(HashAlgorithm hashAlgorithm, SecureRandomGenerator secureRandomGenerator) {
        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("HashAlgorithm cannot be null");
        }
        if (secureRandomGenerator == null) {
            throw new IllegalArgumentException("SecureRandomGenerator cannot be null");
        }
        this.hashAlgorithm = hashAlgorithm;
        this.secureRandomGenerator = secureRandomGenerator;
    }

    /**
     * Generates a Schnorr proof of knowledge.
     *
     * @param statement The public statement (p, q, g, y).
     * @param witness   The secret witness (x).
     * @return The generated SchnorrProof (t, s).
     * @throws IllegalArgumentException if statement or witness is null.
     * @throws ZkpException             if an error occurs during proof generation (e.g., random generation, hashing).
     */
    @Override
    public SchnorrProof generateProof(SchnorrStatement statement, SchnorrWitness witness) throws ZkpException {
        if (statement == null) {
            throw new IllegalArgumentException("Statement cannot be null");
        }
        if (witness == null) {
            throw new IllegalArgumentException("Witness cannot be null");
        }

        BigInteger p = statement.getP();
        BigInteger q = statement.getQ();
        BigInteger g = statement.getG();
        BigInteger y = statement.getY();
        BigInteger x = witness.getX();

        try {
            // 1. Generate random secret v in [1, q-1]
            // Note: generateRandomPositiveBigInteger generates in [0, max-1], so we use q-1 and add 1.
            // Or better, use a method that generates in [1, q-1] if available. Assuming generateRandomBigInteger(q) gives [0, q-1].
            // Let's refine the random generation to be strictly positive and less than q.
            BigInteger v;
            do {
                 // Generates in [0, q-1]. If 0, retry.
                 v = secureRandomGenerator.generateBigInteger(q);
            } while (v.equals(BigInteger.ZERO));


            // 2. Compute commitment t = g^v mod p
            BigInteger t = g.modPow(v, p);

            // 3. Compute challenge c = H(p || q || g || y || t)
            BigInteger c = computeChallenge(p, q, g, y, t);

            // 4. Compute response s = (v - c*x) mod q
            // Ensure the result of (v - c*x) is non-negative before mod q
            BigInteger cx = c.multiply(x).mod(q); // c*x mod q
            BigInteger vMinusCx = v.subtract(cx);
            BigInteger s = vMinusCx.mod(q); // (v - c*x) mod q. Handles negative results correctly.

            return new SchnorrProof(t, s);

        } catch (SecurityUtilException e) {
            throw new ZkpException("Failed to generate random number for proof", e);
        } catch (ArithmeticException e) {
            throw new ZkpException("Arithmetic error during proof generation", e);
        } catch (Exception e) { // Catch broader exceptions during hashing
             throw new ZkpException("Failed to compute challenge hash", e);
        }
    }

    /**
     * Computes the challenge c = H(p || q || g || y || t).
     * Concatenates the string representations of the BigIntegers.
     * A more robust implementation might serialize bytes directly.
     */
    private BigInteger computeChallenge(BigInteger p, BigInteger q, BigInteger g, BigInteger y, BigInteger t) throws SecurityUtilException {
        // Simple concatenation of string representations. Ensure consistent encoding.
        String dataToHash = p.toString() + "|" + q.toString() + "|" + g.toString() + "|" + y.toString() + "|" + t.toString();
        byte[] hashBytes = hashAlgorithm.hash(dataToHash.getBytes(StandardCharsets.UTF_8));
        // Convert hash bytes to a positive BigInteger
        return new BigInteger(1, hashBytes);
    }
}