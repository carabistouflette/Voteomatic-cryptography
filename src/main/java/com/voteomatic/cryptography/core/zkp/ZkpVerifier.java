package com.voteomatic.cryptography.core.zkp;

/**
 * Interface for verifying Zero-Knowledge Proofs (ZKPs). Defines the contract for a verifier
 * component that can check the validity of a proof with respect to a public statement, without
 * learning the secret witness.
 *
 * @param <S> The type representing the public statement.
 * @param <P> The type representing the proof to be verified.
 */
public interface ZkpVerifier<S extends Statement, P extends Proof> {

  /**
   * Verifies a zero-knowledge proof against a public statement.
   *
   * @param statement The public statement.
   * @param proof The proof provided by the prover.
   * @return {@code true} if the proof is valid for the given statement, {@code false} otherwise.
   * @throws ZkpException if verification fails due to an error (e.g., incompatible types, internal
   *     errors).
   */
  boolean verifyProof(S statement, P proof) throws ZkpException;
}
