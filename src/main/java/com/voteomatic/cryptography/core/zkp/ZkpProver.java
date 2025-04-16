package com.voteomatic.cryptography.core.zkp;

/**
 * Interface for generating Zero-Knowledge Proofs (ZKPs). Defines the contract for a prover
 * component that can generate a proof demonstrating knowledge of a secret (witness) related to a
 * public statement, without revealing the witness itself.
 *
 * @param <S> The type representing the public statement.
 * @param <W> The type representing the secret witness.
 * @param <P> The type representing the generated proof.
 */
public interface ZkpProver<S extends Statement, W extends Witness, P extends Proof> {

  /**
   * Generates a zero-knowledge proof.
   *
   * @param statement The public statement about which the proof is being made.
   * @param witness The secret witness known by the prover.
   * @return The generated Proof object.
   * @throws ZkpException if proof generation fails (e.g., invalid inputs, internal errors).
   */
  P generateProof(S statement, W witness) throws ZkpException;
}
