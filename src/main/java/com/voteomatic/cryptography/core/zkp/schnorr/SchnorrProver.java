package com.voteomatic.cryptography.core.zkp.schnorr;

import com.voteomatic.cryptography.core.DomainParameters; // Needed for statement access
import com.voteomatic.cryptography.core.elgamal.PublicKey; // Needed for statement access
import com.voteomatic.cryptography.core.zkp.ZkpChallengeUtils;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpProver;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.math.BigInteger;

// Removed unused imports: java.io.ByteArrayOutputStream, java.io.IOException, java.util.Objects

/**
 * Implements the Prover side of Schnorr's protocol for proving knowledge of a discrete logarithm.
 * Proves knowledge of x such that y = g^x mod p.
 */
public class SchnorrProver implements ZkpProver<SchnorrStatement, SchnorrWitness, SchnorrProof> {

  private final HashAlgorithm hashAlgorithm;
  private final SecureRandomGenerator secureRandomGenerator;

  /**
   * Private constructor for SchnorrProver. Validation is done in the factory method.
   *
   * @param hashAlgorithm The validated hash algorithm.
   * @param secureRandomGenerator The validated secure random generator.
   */
  private SchnorrProver(HashAlgorithm hashAlgorithm, SecureRandomGenerator secureRandomGenerator) {
    this.hashAlgorithm = hashAlgorithm; // Assumed non-null by factory method
    this.secureRandomGenerator = secureRandomGenerator; // Assumed non-null by factory method
  }

  /**
   * Creates a SchnorrProver instance.
   *
   * @param hashAlgorithm The hash algorithm to use for generating the challenge. Must not be null.
   * @param secureRandomGenerator The secure random generator for generating the secret nonce 'v'.
   *     Must not be null.
   * @return A new SchnorrProver instance.
   * @throws IllegalArgumentException if any dependency is null.
   */
  public static SchnorrProver create(
      HashAlgorithm hashAlgorithm, SecureRandomGenerator secureRandomGenerator) {
    if (hashAlgorithm == null) {
      throw new IllegalArgumentException("HashAlgorithm cannot be null");
    }
    if (secureRandomGenerator == null) {
      throw new IllegalArgumentException("SecureRandomGenerator cannot be null");
    }
    return new SchnorrProver(hashAlgorithm, secureRandomGenerator);
  }

  /**
   * Generates a Schnorr proof of knowledge.
   *
   * @param statement The public statement (p, q, g, y).
   * @param witness The secret witness (x).
   * @return The generated SchnorrProof (t, s).
   * @throws IllegalArgumentException if statement or witness is null.
   * @throws ZkpException if an error occurs during proof generation (e.g., random generation,
   *     hashing).
   */
  @Override
  public SchnorrProof generateProof(SchnorrStatement statement, SchnorrWitness witness)
      throws ZkpException {
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
    BigInteger x = witness.getSecretValue();

    BigInteger v;
    try {
      // 1. Generate random secret v in [1, q-1]
      do {
        // Generates in [0, q-1]. If 0, retry.
        v = secureRandomGenerator.generateBigInteger(q);
      } while (v.equals(BigInteger.ZERO));
    } catch (SecurityUtilException e) {
      throw new ZkpException("Failed to generate random number for proof", e);
    }

    try {
      // 2. Compute commitment t = g^v mod p
      BigInteger t = g.modPow(v, p);

      // 3. Compute challenge c = H(p || q || g || y || t) mod q using utility class
      DomainParameters domainParams = new DomainParameters(p, q, g);
      PublicKey pubKey = new PublicKey(domainParams, y);
      BigInteger cHash = // Renamed from c_hash
          ZkpChallengeUtils.computeSchnorrChallenge(domainParams, pubKey, t, hashAlgorithm);
      BigInteger c = cHash.mod(q); // Reduce the hash modulo q

      // 4. Compute response s = (v - c*x) mod q
      BigInteger cx = c.multiply(x).mod(q);
      BigInteger vMinusCx =
          v.subtract(cx); // Renamed from vMinusCx (already compliant, ensuring consistency)
      BigInteger s = vMinusCx.mod(q); // (v - c*x) mod q. Handles negative results correctly.

      // Use the static factory method instead of the private constructor
      return SchnorrProof.create(t, s);

    } catch (SecurityUtilException e) { // Catch hashing exception
      throw new ZkpException("Failed to compute challenge hash for Schnorr proof", e);
    } catch (ArithmeticException e) { // Catch calculation exception
      throw new ZkpException("Arithmetic error during Schnorr proof generation", e);
    }
  }

  // Removed private helper methods: writeBigIntegerWithLength and computeChallenge
}
