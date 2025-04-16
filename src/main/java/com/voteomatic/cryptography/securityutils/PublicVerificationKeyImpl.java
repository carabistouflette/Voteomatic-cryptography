package com.voteomatic.cryptography.securityutils;

import java.security.PublicKey;
import java.util.Objects;

/**
 * A concrete implementation of PublicVerificationKey, wrapping a standard java.security.PublicKey.
 */
public class PublicVerificationKeyImpl implements PublicVerificationKey {

  private final PublicKey publicKey;

  /**
   * Constructs a PublicVerificationKeyImpl.
   *
   * @param publicKey The underlying java.security.PublicKey. Must not be null.
   */
  public PublicVerificationKeyImpl(PublicKey publicKey) {
    this.publicKey = Objects.requireNonNull(publicKey, "PublicKey cannot be null.");
  }

  /**
   * Gets the underlying JCA PublicKey object. This method provides access to the raw key material
   * needed by underlying JCA providers.
   *
   * @return The java.security.PublicKey instance.
   */
  public PublicKey getJcaPublicKey() {
    return publicKey;
  }

  @Override
  public String getAlgorithm() {
    return publicKey.getAlgorithm();
  }

  @Override
  public byte[] getEncoded() {
    // Return a copy to prevent modification of the internal state if the key is mutable
    // (though PublicKey is generally immutable, this is safer).
    byte[] encoded = publicKey.getEncoded();
    return (encoded != null) ? encoded.clone() : null;
  }

  // Note: equals() and hashCode() are not implemented. Comparison relies on object identity.
  // Consider implementing them if needed for collections or comparisons based on key material.
}
