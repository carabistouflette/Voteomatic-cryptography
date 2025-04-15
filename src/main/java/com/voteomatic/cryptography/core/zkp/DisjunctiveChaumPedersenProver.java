package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.DomainParameters; // Added
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;

import java.math.BigInteger;
import java.util.Objects;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
                                          BigInteger q) throws SecurityUtilException, ZkpException { // Added ZkpException

       // Serialize inputs using length-prefixing for unambiguous hashing
       byte[] inputBytes;
       try {
           inputBytes = serializeForChallenge(p, g, h, c1, c2, m0, m1, a0, b0, a1, b1);
       } catch (IOException e) {
           // Wrap IOException in ZkpException as it indicates a failure in proof generation logic
           throw new ZkpException("Failed to serialize data for challenge generation: " + e.getMessage(), e);
       }

       byte[] hash = hashAlgorithm.hash(inputBytes);
       BigInteger challenge = new BigInteger(1, hash); // Ensure positive BigInteger

       // Reduce the challenge modulo q
       return challenge.mod(q);
   }

   /**
    * Serializes multiple BigIntegers into a single byte array using length-prefixing.
    * Each BigInteger's byte array (from toByteArray()) is preceded by its length
    * encoded as a 4-byte big-endian integer. This ensures unambiguous parsing.
    *
    * @param values The BigIntegers to serialize.
    * @return A byte array containing the length-prefixed serialized data.
    * @throws IOException If an I/O error occurs during serialization.
    */
   private byte[] serializeForChallenge(BigInteger... values) throws IOException {
       ByteArrayOutputStream baos = new ByteArrayOutputStream();
       for (BigInteger val : values) {
           byte[] bytes = val.toByteArray();
           int length = bytes.length;
           // Write length as 4-byte big-endian integer
           baos.write((length >> 24) & 0xFF);
           baos.write((length >> 16) & 0xFF);
           baos.write((length >> 8) & 0xFF);
           baos.write(length & 0xFF);
           // Write the actual byte data
           baos.write(bytes);
       }
       return baos.toByteArray();
   }

}