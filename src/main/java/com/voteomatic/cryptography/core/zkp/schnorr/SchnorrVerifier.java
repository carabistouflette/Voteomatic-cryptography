package com.voteomatic.cryptography.core.zkp.schnorr;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.ZkpChallengeUtils;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpVerifier;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.math.BigInteger;

/**
 * Implements the Verifier side of Schnorr's protocol. Verifies a proof of knowledge of x for a
 * given statement y = g^x mod p.
 */
public class SchnorrVerifier implements ZkpVerifier<SchnorrStatement, SchnorrProof> {

  private final HashAlgorithm hashAlgorithm;

  /**
   * Private constructor for SchnorrVerifier. Validation is done in the factory method.
   *
   * @param hashAlgorithm The validated hash algorithm.
   */
  private SchnorrVerifier(HashAlgorithm hashAlgorithm) {
    this.hashAlgorithm = hashAlgorithm; // Assumed non-null by factory method
  }

  /**
   * Creates a SchnorrVerifier instance.
   *
   * @param hashAlgorithm The hash algorithm used to generate the challenge. Must be the same
   *     instance/type as used by the prover. Must not be null.
   * @return A new SchnorrVerifier instance.
   * @throws IllegalArgumentException if hashAlgorithm is null.
   */
  public static SchnorrVerifier create(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm == null) {
      throw new IllegalArgumentException("HashAlgorithm cannot be null");
    }
    return new SchnorrVerifier(hashAlgorithm);
  }

  /**
   * Verifies a Schnorr proof.
   *
   * @param statement The public statement (p, q, g, y).
   * @param proof The proof (t, s) to verify.
   * @return true if the proof is valid, false otherwise.
   * @throws IllegalArgumentException if statement or proof is null.
   * @throws ZkpException if an error occurs during verification (e.g., hashing or arithmetic).
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
    BigInteger q = statement.getQ(); // q is needed for challenge computation
    BigInteger g = statement.getG();
    BigInteger y = statement.getY();
    BigInteger t = proof.getT();
    BigInteger s = proof.getS();

    // Basic validation: Check if t and s are within expected ranges
    if (t.compareTo(BigInteger.ONE) < 0 || t.compareTo(p) >= 0) {
      return false; // t must be in the group Z_p^*
    }
    if (s.compareTo(BigInteger.ZERO) < 0 || s.compareTo(q) >= 0) {
      return false; // s must be in Z_q
    }

    try {
      // 1. Re-compute challenge c = H(p || q || g || y || t) mod q using utility class
      DomainParameters domainParams = new DomainParameters(p, q, g);
      PublicKey pubKey = new PublicKey(domainParams, y);
      BigInteger cHash = // Renamed from c_hash
          ZkpChallengeUtils.computeSchnorrChallenge(domainParams, pubKey, t, hashAlgorithm);
      BigInteger c = cHash.mod(q); // Reduce the hash modulo q

      // 2. Compute check1 = g^s mod p
      BigInteger check1 = g.modPow(s, p);

      // 3. Compute check2 = y^c mod p
      BigInteger check2 = y.modPow(c, p);

      // 4. Compute t' = (check1 * check2) mod p
      BigInteger tPrime = check1.multiply(check2).mod(p); // Renamed from t_prime

      // 5. Compare t' with the commitment t from the proof
      return tPrime.equals(t);

    } catch (SecurityUtilException e) {
      // Catch hashing exception from ZkpChallengeUtils
      throw new ZkpException("Failed to compute challenge hash during verification", e);
    } catch (ArithmeticException e) {
      // This might happen if, e.g., p is not prime or g is not a generator,
      // leading to unexpected results in modPow.
      throw new ZkpException("Arithmetic error during proof verification", e);
    }
  }

  // Removed private helper methods: writeBigIntegerWithLength and computeChallenge
}
