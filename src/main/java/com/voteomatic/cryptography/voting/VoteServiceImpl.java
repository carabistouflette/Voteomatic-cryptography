package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.*;
import com.voteomatic.cryptography.keymanagement.KeyService;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * Implementation of the VoteService interface.
 */
public class VoteServiceImpl implements VoteService {

    private final ElGamalCipher elGamalCipher;
    private final KeyService keyService; // Although specified, it's not used in the current methods. Included for completeness.
    private final ZkpProver prover; // Specifically SchnorrProver expected
    private final ZkpVerifier verifier; // Specifically SchnorrVerifier expected

    /**
     * Constructs a VoteServiceImpl with required dependencies.
     *
     * @param elGamalCipher The ElGamal cipher implementation.
     * @param keyService    The key service implementation.
     * @param prover        The Zero-Knowledge Proof prover (e.g., SchnorrProver).
     * @param verifier      The Zero-Knowledge Proof verifier (e.g., SchnorrVerifier).
     */
    public VoteServiceImpl(ElGamalCipher elGamalCipher, KeyService keyService, ZkpProver prover, ZkpVerifier verifier) {
        this.elGamalCipher = Objects.requireNonNull(elGamalCipher, "ElGamalCipher cannot be null");
        this.keyService = Objects.requireNonNull(keyService, "KeyService cannot be null");
        this.prover = Objects.requireNonNull(prover, "ZkpProver cannot be null");
        this.verifier = Objects.requireNonNull(verifier, "ZkpVerifier cannot be null");

        // Optional: Add checks to ensure prover/verifier are Schnorr instances if strictly required
        // if (!(prover instanceof SchnorrProver)) {
        //     throw new IllegalArgumentException("Prover must be an instance of SchnorrProver");
        // }
        // if (!(verifier instanceof SchnorrVerifier)) {
        //     throw new IllegalArgumentException("Verifier must be an instance of SchnorrVerifier");
        // }
    }

    @Override
    public EncryptedVote castVote(VoterCredentials credentials, Vote vote, PublicKey electionPublicKey) throws VotingException {
        Objects.requireNonNull(credentials, "VoterCredentials cannot be null");
        Objects.requireNonNull(vote, "Vote cannot be null");
        Objects.requireNonNull(electionPublicKey, "Election PublicKey cannot be null");

        try {
            // Vote Encoding: Convert selected option string to BigInteger via UTF-8 bytes.
            // This assumes the numerical value of the byte representation is meaningful
            // within the context of ElGamal encryption and tallying (homomorphic addition).
            // Ensure the group order 'p' of the public key is large enough.
            String selectedOption = vote.getSelectedOption();
            if (selectedOption == null || selectedOption.isEmpty()) {
                throw new IllegalArgumentException("Vote option cannot be null or empty");
            }
            byte[] voteBytes = selectedOption.getBytes(StandardCharsets.UTF_8);
            BigInteger message = new BigInteger(1, voteBytes); // Use 1 for positive signum

            // Validate message size against ElGamal parameters (p)
            if (message.compareTo(electionPublicKey.getP()) >= 0) {
                throw new VotingException("Vote encoding results in a value too large for the ElGamal parameters.");
            }

            // Encrypt the vote message
            Ciphertext voteCiphertext = elGamalCipher.encrypt(electionPublicKey, message); // Corrected argument order

            // ZKP Generation is skipped for this iteration. Proof is null.
            Proof proof = null;

            return new EncryptedVote(voteCiphertext, proof); // Corrected constructor call

        } catch (IllegalArgumentException e) {
            throw e; // Re-throw specific argument exceptions
        } catch (Exception e) {
            // Wrap other potential exceptions (e.g., from encryption)
            throw new VotingException("Error casting vote: " + e.getMessage(), e);
        }
    }

    @Override
    public Object tallyVotes(List<EncryptedVote> encryptedVotes, PrivateKey electionPrivateKey) throws VotingException {
        Objects.requireNonNull(encryptedVotes, "Encrypted votes list cannot be null");
        Objects.requireNonNull(electionPrivateKey, "Election PrivateKey cannot be null");

        BigInteger tallySum = BigInteger.ZERO;

        for (EncryptedVote encryptedVote : encryptedVotes) {
            if (encryptedVote == null || encryptedVote.getVoteCiphertext() == null) {
                // Decide how to handle invalid entries: skip, throw exception, etc.
                // Skipping for now, but logging might be appropriate.
                System.err.println("Warning: Skipping null or invalid encrypted vote entry.");
                continue;
            }

            try {
                Ciphertext voteCiphertext = encryptedVote.getVoteCiphertext();
                BigInteger decryptedMessage = elGamalCipher.decrypt(electionPrivateKey, voteCiphertext); // Corrected argument order
                // Assuming the encoded votes are intended to be summed directly.
                tallySum = tallySum.add(decryptedMessage);
            } catch (Exception e) {
                // Handle decryption errors. Depending on policy, might invalidate the whole tally
                // or just log the specific error and continue. Throwing for now.
                // Voter ID is not available on EncryptedVote, adjust error message
                throw new VotingException("Error decrypting a vote during tally: " + e.getMessage(), e);
            }
        }

        // The interface returns Object, but BigInteger is the actual result type here.
        return tallySum;
    }

    @Override
    public boolean verifyVote(EncryptedVote encryptedVote, Statement statement, Proof proof) throws VotingException, ZkpException {
        Objects.requireNonNull(encryptedVote, "EncryptedVote cannot be null");
        // Statement and Proof can be null if ZKP is not used/provided.

        // As per requirements, ZKP generation is skipped in castVote, so proof will be null.
        if (proof == null) {
            // If no proof is provided (as expected in this iteration), verification cannot proceed.
            // Depending on the desired behavior, could return false or throw an exception.
            // Returning false seems appropriate given the context.
            return false;
        }

        // Check if the provided statement and proof are of the expected Schnorr types.
        if (!(statement instanceof SchnorrStatement)) {
             throw new IllegalArgumentException("Statement must be an instance of SchnorrStatement for verification.");
           // return false; // Alternatively, just return false if type mismatch means invalid proof
        }
        if (!(proof instanceof SchnorrProof)) {
             throw new IllegalArgumentException("Proof must be an instance of SchnorrProof for verification.");
           // return false; // Alternatively, just return false
        }

        // Cast to specific types
        SchnorrStatement schnorrStatement = (SchnorrStatement) statement;
        SchnorrProof schnorrProof = (SchnorrProof) proof;

        try {
            // Use the injected ZkpVerifier (expected to be SchnorrVerifier)
            return verifier.verifyProof(schnorrStatement, schnorrProof);
        } catch (ZkpException e) {
            // Propagate ZKP-specific exceptions
            throw e;
        } catch (Exception e) {
            // Wrap unexpected errors during verification
            throw new VotingException("Unexpected error during vote verification: " + e.getMessage(), e);
        }
    }
}