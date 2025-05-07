package com.voteomatic.cryptography.core.zkp.chaumpedersen;

import com.voteomatic.cryptography.core.DomainParameters; // Added
import com.voteomatic.cryptography.core.zkp.Proof;
import com.voteomatic.cryptography.core.zkp.Statement;
import com.voteomatic.cryptography.core.zkp.Witness;
import com.voteomatic.cryptography.core.zkp.ZkpChallengeUtils;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpProver;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
// Removed unused imports: java.io.ByteArrayOutputStream, java.io.IOException
import java.math.BigInteger;
import java.util.Objects;

/**
 * Implements the prover logic for the Disjunctive Chaum-Pedersen ZKP scheme. Generates a proof that
 * an ElGamal ciphertext encrypts one of two known messages.
 */
public class DisjunctiveChaumPedersenProver implements ZkpProver {

  private final SecureRandomGenerator randomGenerator;
  private final HashAlgorithm hashAlgorithm;

  /**
   * Constructs a DisjunctiveChaumPedersenProver.
   *
   * @param randomGenerator The secure random number generator.
   * @param hashAlgorithm The hash algorithm to use for challenge generation.
   */
  public DisjunctiveChaumPedersenProver(
      SecureRandomGenerator randomGenerator, HashAlgorithm hashAlgorithm) {
    this.randomGenerator =
        Objects.requireNonNull(randomGenerator, "SecureRandomGenerator cannot be null");
    this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "HashAlgorithm cannot be null");
  }

  @Override
  public Proof generateProof(Statement statement, Witness witness) throws ZkpException {
    if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
      throw new IllegalArgumentException(
          "Statement must be an instance of DisjunctiveChaumPedersenStatement");
    }
    if (!(witness instanceof DisjunctiveChaumPedersenWitness)) {
      throw new IllegalArgumentException(
          "Witness must be an instance of DisjunctiveChaumPedersenWitness");
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
    int v = wit.getV(); // Actual message index (0 or 1)

    // Removed incorrect calculation: q = p - 1
    // q is now correctly retrieved from DomainParameters

    try {
      BigInteger a0;
      BigInteger b0;
      BigInteger r0;
      BigInteger c0;
      BigInteger c; // Declare c here
      BigInteger a1;
      BigInteger b1;
      BigInteger r1;
      BigInteger c1_challenge; // Renamed c1 to c1_challenge to avoid confusion with ciphertext c1

      if (v == 0) { // Real proof for m0, simulate for m1
        // Simulate for v=1
        // Generate random values in [0, q-1]
        c1_challenge =
            randomGenerator.generateBigInteger(q); // Random challenge for simulated branch
        r1 = randomGenerator.generateBigInteger(q); // Random response for simulated branch

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
        BigInteger w0 =
            randomGenerator.generateBigInteger(q); // Real random commitment value in [0, q-1]
        a0 = g.modPow(w0, p);
        b0 = h.modPow(w0, p);

        // Calculate overall challenge c = H(public values || commitments) using utility class
        c =
            ZkpChallengeUtils.computeDisjunctiveChaumPedersenChallenge(
                stmt, a0, b0, a1, b1, hashAlgorithm);

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
        BigInteger w1 =
            randomGenerator.generateBigInteger(q); // Real random commitment value in [0, q-1]
        a1 = g.modPow(w1, p);
        b1 = h.modPow(w1, p);

        // Calculate overall challenge c = H(public values || commitments) using utility class
        c =
            ZkpChallengeUtils.computeDisjunctiveChaumPedersenChallenge(
                stmt, a0, b0, a1, b1, hashAlgorithm);

        // Calculate real challenge c1 = c - c0 mod q
        c1_challenge = c.subtract(c0).mod(q);

        // Calculate real response r1 = w1 + c1 * r mod q
        r1 = w1.add(c1_challenge.multiply(r)).mod(q);
      }

      // Return proof with individual challenges and responses
      return new DisjunctiveChaumPedersenProof(a0, b0, c0, r0, a1, b1, c1_challenge, r1);

    } catch (SecurityUtilException | ArithmeticException e) {
      throw new ZkpException(
          "Failed to generate Disjunctive Chaum-Pedersen proof: " + e.getMessage(), e);
    }
  }

  // Removed private helper methods: calculateChallenge and serializeForChallenge
}
