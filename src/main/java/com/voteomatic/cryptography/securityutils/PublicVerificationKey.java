package com.voteomatic.cryptography.securityutils;

/**
 * Marker interface for a public key used for verifying digital signatures. Concrete implementations
 * will hold the specific key material for a given signature algorithm (e.g., RSA public exponent
 * and modulus, ECDSA public point). This key can be shared publicly.
 */
public interface PublicVerificationKey {
  // Marker interface - details depend on the specific signature algorithm.

  /**
   * Gets the standard algorithm name associated with this key (e.g., "RSA", "ECDSA"). Should match
   * the algorithm of the corresponding PrivateSigningKey.
   *
   * @return The algorithm name.
   */
  String getAlgorithm();

  /**
   * Gets the encoded form of the public key. Useful for serialization or transport. The format
   * depends on the implementation.
   *
   * @return The encoded public key as a byte array, or null if not supported.
   */
  byte[] getEncoded();
}
