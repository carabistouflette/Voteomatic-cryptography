package com.voteomatic.cryptography.core.zkp;

/**
 * Marker interface for a secret witness in a Zero-Knowledge Proof. Concrete implementations will
 * define the specific secret data known by the prover that satisfies the public statement (e.g.,
 * the discrete logarithm itself).
 */
public interface Witness {
  // Marker interface - no methods required at this base level.
  // Implementations will contain the actual witness data.
}
