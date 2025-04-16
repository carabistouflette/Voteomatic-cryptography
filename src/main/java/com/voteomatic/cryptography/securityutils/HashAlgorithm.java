package com.voteomatic.cryptography.securityutils;

/**
 * Interface for cryptographic hash functions. Defines a contract for services that compute
 * fixed-size hash digests from arbitrary input data.
 */
public interface HashAlgorithm {

  /**
   * Computes the hash digest of the given input data.
   *
   * @param data The input data to hash. Must not be null.
   * @return The computed hash digest as a byte array.
   * @throws SecurityUtilException if hashing fails (e.g., internal algorithm error).
   */
  byte[] hash(byte[] data) throws SecurityUtilException;

  /**
   * Gets the standard algorithm name (e.g., "SHA-256", "SHA3-512"). Useful for identifying the
   * specific algorithm implementation.
   *
   * @return The standard name of the hash algorithm.
   */
  String getAlgorithmName();

  /**
   * Gets the output size of the hash digest in bytes.
   *
   * @return The length of the hash digest in bytes.
   */
  int getDigestLength();
}
