package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.*;
import com.voteomatic.cryptography.keymanagement.KeyService;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Implementation of the VoteService interface.
 */
public class VoteServiceImpl implements VoteService {

    private final ElGamalCipher elGamalCipher;
    private final KeyService keyService;
    private final ZkpProver prover;
    private final ZkpVerifier verifier;

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
            // Vote Encoding for Additive Homomorphism (Exponential ElGamal):
            // Encode a vote as g^1 mod p. The message to encrypt is g itself.
            // This allows E(m1) * E(m2) = E(m1 + m2) when messages are exponents.
            BigInteger p = electionPublicKey.getP();
            BigInteger g = electionPublicKey.getG();
            BigInteger message = g; // Message is g^1 = g

            // No need to validate message size here as g is part of the valid group elements.

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

        if (encryptedVotes.isEmpty()) {
            // Return encryption of 0, which is (1,1) in this context, then decrypt it.
            // Or handle as appropriate (e.g., throw exception, return specific value).
            // Decrypting (1,1) should yield g^0 = 1.
             try {
                 // Assuming decrypt can handle the identity ciphertext (1,1) correctly.
                 // The identity ciphertext E(0) = (g^k, y^k * g^0) = (g^k, y^k).
                 // A simpler multiplicative identity is (1, 1). Decrypting (1,1) might not yield 1 directly.
                 // Let's return BigInteger.ONE representing g^0.
                 // Alternatively, encrypt BigInteger.ONE (representing g^0) and decrypt that.
                 // For simplicity, if no votes, the tally (g^T) is g^0 = 1.
                 return BigInteger.ONE;
             } catch (Exception e) {
                 throw new VotingException("Error handling empty vote list: " + e.getMessage(), e);
             }
        }

        BigInteger p = electionPrivateKey.getP();

        // Initialize the combined ciphertext with the identity element for multiplication (1, 1).
        // This represents the encryption of 0 in the exponent (g^0).
        Ciphertext combinedCiphertext = new Ciphertext(BigInteger.ONE, BigInteger.ONE);

        for (EncryptedVote encryptedVote : encryptedVotes) {
            if (encryptedVote == null || encryptedVote.getVoteCiphertext() == null) {
                System.err.println("Warning: Skipping null or invalid encrypted vote entry during tally.");
                continue; // Skip invalid entries
            }

            Ciphertext currentCiphertext = encryptedVote.getVoteCiphertext();
            if (currentCiphertext.getC1() == null || currentCiphertext.getC2() == null) {
                 System.err.println("Warning: Skipping encrypted vote with null ciphertext components.");
                 continue;
            }

            // Homomorphically add (multiply ciphertexts)
            BigInteger newC1 = combinedCiphertext.getC1().multiply(currentCiphertext.getC1()).mod(p);
            BigInteger newC2 = combinedCiphertext.getC2().multiply(currentCiphertext.getC2()).mod(p);
            combinedCiphertext = new Ciphertext(newC1, newC2);
        }

        try {
            // Decrypt the final combined ciphertext. The result is g^T mod p, where T is the total count.
            BigInteger decryptedResult = elGamalCipher.decrypt(electionPrivateKey, combinedCiphertext);
            // The caller needs to solve the discrete log problem if they need T itself.
            // We return g^T mod p as per the homomorphic result.
            return decryptedResult;
        } catch (Exception e) {
            throw new VotingException("Error decrypting final tally: " + e.getMessage(), e);
        }
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