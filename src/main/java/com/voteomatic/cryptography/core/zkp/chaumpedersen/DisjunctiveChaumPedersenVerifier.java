package com.voteomatic.cryptography.core.zkp.chaumpedersen;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.zkp.Proof;
import com.voteomatic.cryptography.core.zkp.Statement;
import com.voteomatic.cryptography.core.zkp.ZkpChallengeUtils;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpVerifier;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Implements the verifier logic for the Disjunctive Chaum-Pedersen ZKP scheme. Verifies a proof
 * that an ElGamal ciphertext encrypts one of two known messages.
 */
public class DisjunctiveChaumPedersenVerifier implements ZkpVerifier {

  private final HashAlgorithm hashAlgorithm;

  /**
   * Constructs a DisjunctiveChaumPedersenVerifier.
   *
   * @param hashAlgorithm The hash algorithm to use for challenge recalculation.
   */
  public DisjunctiveChaumPedersenVerifier(HashAlgorithm hashAlgorithm) {
    this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "HashAlgorithm cannot be null");
  }

  @Override
  public boolean verifyProof(Statement statement, Proof proof) throws ZkpException {
    if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
      throw new IllegalArgumentException(
          "Statement must be an instance of DisjunctiveChaumPedersenStatement");
    }
    if (!(proof instanceof DisjunctiveChaumPedersenProof)) {
      throw new IllegalArgumentException(
          "Proof must be an instance of DisjunctiveChaumPedersenProof");
    }

    DisjunctiveChaumPedersenStatement stmt = (DisjunctiveChaumPedersenStatement) statement;
    DisjunctiveChaumPedersenProof prf = (DisjunctiveChaumPedersenProof) proof;

    // Retrieve parameters from the statement
    DomainParameters params = stmt.getParams();
    BigInteger p = params.getP();
    BigInteger g = params.getG();
    BigInteger q = params.getQ(); // Use the correct subgroup order q
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
    BigInteger c1_challenge = prf.getC1();
    BigInteger r1 = prf.getR1();

    try {
      // 1. Recalculate the overall challenge c' = H(public values || commitments)
      // Use the same serialization as the prover via the utility class.
      BigInteger calculated_c =
          ZkpChallengeUtils.computeDisjunctiveChaumPedersenChallenge(
              stmt, a0, b0, a1, b1, hashAlgorithm);

      // 2. Check if c' == c0 + c1 (mod q)
      boolean challengeCheck = calculated_c.equals(c0.add(c1_challenge).mod(q));
      if (!challengeCheck) {
        return false;
      }

      // 3. Verify first equation for v=0: g^r0 == a0 * c1^c0 (mod p)
      BigInteger g_pow_r0 = g.modPow(r0, p);
      BigInteger c1_pow_c0 = c1.modPow(c0, p);
      BigInteger check0_lhs = a0.multiply(c1_pow_c0).mod(p);
      boolean check0_eq1 = g_pow_r0.equals(check0_lhs);
      if (!check0_eq1) {
        return false;
      }

      // 4. Verify second equation for v=0: h^r0 == b0 * (c2/m0)^c0 (mod p)
      BigInteger h_pow_r0 = h.modPow(r0, p);
      BigInteger c2_div_m0 = c2.multiply(m0.modInverse(p)).mod(p);
      BigInteger c2_div_m0_pow_c0 = c2_div_m0.modPow(c0, p);
      BigInteger check0_rhs = b0.multiply(c2_div_m0_pow_c0).mod(p);
      boolean check0_eq2 = h_pow_r0.equals(check0_rhs);
      if (!check0_eq2) {
        return false;
      }

      // 5. Verify first equation for v=1: g^r1 == a1 * c1^c1 (mod p)
      BigInteger g_pow_r1 = g.modPow(r1, p);
      BigInteger c1_pow_c1 = c1.modPow(c1_challenge, p);
      BigInteger check1_lhs = a1.multiply(c1_pow_c1).mod(p);
      boolean check1_eq1 = g_pow_r1.equals(check1_lhs);
      if (!check1_eq1) {
        return false;
      }

      // 6. Verify second equation for v=1: h^r1 == b1 * (c2/m1)^c1 (mod p)
      BigInteger h_pow_r1 = h.modPow(r1, p);
      BigInteger c2_div_m1 = c2.multiply(m1.modInverse(p)).mod(p);
      BigInteger c2_div_m1_pow_c1 = c2_div_m1.modPow(c1_challenge, p);
      BigInteger check1_rhs = b1.multiply(c2_div_m1_pow_c1).mod(p);
      boolean check1_eq2 = h_pow_r1.equals(check1_rhs);
      if (!check1_eq2) {
        return false;
      }

      // If all checks pass, the proof is valid
      return true;

    } catch (ArithmeticException | ZkpException | SecurityUtilException e) {
      // Treat calculation errors or serialization/hashing errors during verification as proof
      // failure
      // Log the error for debugging if necessary
      // System.err.println("Error during verification: " + e.getMessage());
      return false;
      // Or rethrow as ZkpException if that's preferred behavior
      // throw new ZkpException("Verification failed due to calculation error: " + e.getMessage(),
      // e);
    }
  }
}
