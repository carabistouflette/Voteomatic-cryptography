package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.Proof;
import com.voteomatic.cryptography.core.zkp.Statement;
import com.voteomatic.cryptography.core.zkp.ZkpException; // Needed for verifyVote

import java.util.List;

/**
 * Interface for core voting protocol operations.
 * Defines the contract for services handling vote casting, verification, and tallying.
 */
public interface VoteService {

    /**
     * Casts a vote by encrypting it with the election's public key and potentially
     * generating a proof of validity.
     *
     * @param voter             The credentials of the voter casting the vote.
     * @param vote              The plaintext vote content.
     * @param electionPublicKey The public key of the election authority used for encryption.
     * @return An EncryptedVote object containing the ciphertext and any associated proof.
     * @throws VotingException if casting the vote fails (e.g., encryption error, invalid input).
     * @throws ZkpException    if proof generation fails.
     */
    EncryptedVote castVote(VoterCredentials voter, Vote vote, PublicKey electionPublicKey)
            throws VotingException, ZkpException;

    /**
     * Tallies a list of encrypted votes using the election's private key.
     * The exact return type depends on the tallying method (e.g., simple sum for homomorphic encryption).
     *
     * @param encryptedVotes       The list of encrypted votes to tally.
     * @param electionPrivateKey The private key corresponding to the election public key, required for decryption.
     * @return The result of the tally (e.g., a BigInteger representing the sum of encrypted values, or a more complex structure).
     * @throws VotingException if tallying fails (e.g., decryption error, invalid votes).
     */
    // Note: Return type might need refinement based on specific ElGamal usage (e.g., summing BigIntegers)
    Object tallyVotes(List<EncryptedVote> encryptedVotes, PrivateKey electionPrivateKey)
            throws VotingException;

    /**
     * Verifies an individual encrypted vote, typically using an associated Zero-Knowledge Proof.
     *
     * @param vote      The EncryptedVote to verify.
     * @param statement The public statement related to the proof (e.g., parameters, ciphertext).
     * @param proof     The proof provided with the vote.
     * @return true if the vote and its proof are valid, false otherwise.
     * @throws VotingException if the verification process encounters an issue beyond proof validity.
     * @throws ZkpException    if the underlying ZKP verification fails due to an error.
     */
    boolean verifyVote(EncryptedVote vote, Statement statement, Proof proof)
            throws VotingException, ZkpException;

}