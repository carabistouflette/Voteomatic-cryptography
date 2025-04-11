package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.*; // Import EncryptionResult
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

        // Validate vote option
        String selectedOption = vote.getSelectedOption();
        if (selectedOption == null || selectedOption.isEmpty()) {
            throw new IllegalArgumentException("Vote option cannot be null or empty");
        }

        try {
            // Encode vote string ("Yes"/"No") to group element (g^1 / g^0)
            BigInteger p = electionPublicKey.getP();
            BigInteger g = electionPublicKey.getG();
            BigInteger message;

            if ("Yes".equalsIgnoreCase(selectedOption)) {
                message = g; // g^1 mod p
            } else if ("No".equalsIgnoreCase(selectedOption)) {
                message = BigInteger.ONE; // g^0 mod p
            } else {
                throw new VotingException("Invalid vote option: '" + selectedOption + "'. Only 'Yes' or 'No' are allowed.");
            }

            // Basic validation (g^1 and g^0 should always be < p if parameters are valid)
            // This check might be redundant if key generation ensures g < p, but kept for safety.
            if (message.compareTo(p) >= 0) {
                // This case should theoretically not happen with g^1 or g^0 encoding
                throw new VotingException("Encoded vote value is unexpectedly too large for the ElGamal parameters.");
            }

            // Encrypt the encoded vote message and get randomness
            EncryptionResult encryptionResult = elGamalCipher.encrypt(electionPublicKey, message);
            Ciphertext voteCiphertext = encryptionResult.getCiphertext();
            BigInteger randomness = encryptionResult.getRandomness(); // The 'r' value

            // Determine vote index v (0 for No, 1 for Yes) and possible messages m0, m1
            int voteIndex;
            BigInteger m0 = BigInteger.ONE; // g^0
            BigInteger m1 = g;             // g^1
            if ("Yes".equalsIgnoreCase(selectedOption)) {
                voteIndex = 1;
            } else { // Must be "No" due to earlier validation
                voteIndex = 0;
            }

            // Create ZKP Statement and Witness
            DisjunctiveChaumPedersenStatement statement = new DisjunctiveChaumPedersenStatement(
                    electionPublicKey, voteCiphertext, m0, m1
            );
            DisjunctiveChaumPedersenWitness witness = new DisjunctiveChaumPedersenWitness(randomness, voteIndex);

            // Generate the ZKP proof using the injected prover
            // Assumes the injected prover is configured as DisjunctiveChaumPedersenProver
            Proof proof = prover.generateProof(statement, witness);

            // Return EncryptedVote with ciphertext and proof
            return new EncryptedVote(voteCiphertext, proof);

        } catch (IllegalArgumentException e) {
            throw e; // Re-throw specific argument exceptions (e.g., from encoding)
        } catch (Exception e) {
            // Wrap other potential exceptions (e.g., from encryption)
            throw new VotingException("Error casting vote: " + e.getMessage(), e);
        }
    }

    @Override
    public BigInteger tallyVotes(List<EncryptedVote> encryptedVotes, PrivateKey electionPrivateKey) throws VotingException {
        Objects.requireNonNull(encryptedVotes, "Encrypted votes list cannot be null");
        Objects.requireNonNull(electionPrivateKey, "Election PrivateKey cannot be null");

        if (encryptedVotes.isEmpty()) {
            // If there are no votes, the tally k is 0.
            return BigInteger.ZERO;
        }

        BigInteger p = electionPrivateKey.getP(); // Get modulus from private key

        // Initialize accumulated ciphertext with the identity element (1, 1)
        Ciphertext accumulatedCiphertext = new Ciphertext(BigInteger.ONE, BigInteger.ONE);

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

            try {
                // Homomorphically multiply the ciphertexts
                accumulatedCiphertext = accumulatedCiphertext.multiply(currentCiphertext, p);
            } catch (Exception e) {
                // Handle potential errors during multiplication (e.g., nulls if checks fail, though added)
                throw new VotingException("Error multiplying ciphertexts during tally: " + e.getMessage(), e);
            }
        }

        try {
            // Decrypt the final accumulated ciphertext
            BigInteger decryptedResultGk = elGamalCipher.decrypt(electionPrivateKey, accumulatedCiphertext); // This is g^k mod p

            // Find k by solving the discrete logarithm g^k = decryptedResultGk (mod p)
            // Since k represents the count of "Yes" votes (encoded as g^1),
            // we can find it by trial exponentiation for small k.
            BigInteger g = electionPrivateKey.getG();
            BigInteger currentGPower = BigInteger.ONE; // Start with g^0
            BigInteger k = BigInteger.ZERO;

            // Set a reasonable limit to prevent infinite loops in unexpected scenarios
            // The maximum possible value for k is the number of votes cast.
            int maxIterations = encryptedVotes.size();

            for (int i = 0; i <= maxIterations; i++) {
                if (currentGPower.equals(decryptedResultGk)) {
                    return k; // Found the tally k
                }
                // Calculate next power: g^(i+1) = g^i * g mod p
                currentGPower = currentGPower.multiply(g).mod(p);
                k = k.add(BigInteger.ONE);
            }

            // If the loop finishes without finding k, something is wrong.
            // This might happen if the decrypted result is not a power of g,
            // indicating potential corruption or an issue in the crypto implementation.
            throw new VotingException("Could not determine the vote tally (k) from the decrypted result (g^k). Decrypted value: " + decryptedResultGk);

        } catch (Exception e) {
            // Wrap decryption or tally interpretation error
            throw new VotingException("Error during final tally decryption or interpretation: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verifyVote(EncryptedVote encryptedVote, Statement statement, Proof proof) throws VotingException, ZkpException {
        // EncryptedVote parameter is currently unused but kept for signature compatibility.
        // A better design might reconstruct the statement internally using the public key.
        Objects.requireNonNull(statement, "Statement cannot be null for verification");
        Objects.requireNonNull(proof, "Proof cannot be null for verification");

        // Check if the provided statement and proof are of the expected DisjunctiveChaumPedersen types.
        if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
             throw new IllegalArgumentException("Statement must be an instance of DisjunctiveChaumPedersenStatement for verification.");
           // return false; // Alternatively, just return false if type mismatch means invalid proof
        }
        if (!(proof instanceof DisjunctiveChaumPedersenProof)) {
             throw new IllegalArgumentException("Proof must be an instance of DisjunctiveChaumPedersenProof for verification.");
           // return false; // Alternatively, just return false
        }

        // Cast to specific types
        DisjunctiveChaumPedersenStatement dcpStatement = (DisjunctiveChaumPedersenStatement) statement;
        DisjunctiveChaumPedersenProof dcpProof = (DisjunctiveChaumPedersenProof) proof;

        try {
            // Use the injected ZkpVerifier (expected to be SchnorrVerifier)
            // Use the injected ZkpVerifier (expected to be DisjunctiveChaumPedersenVerifier)
            return verifier.verifyProof(dcpStatement, dcpProof);
        } catch (ZkpException e) {
            // Propagate ZKP-specific exceptions
            throw e;
        } catch (Exception e) {
            // Wrap unexpected errors during verification
            throw new VotingException("Unexpected error during vote verification: " + e.getMessage(), e);
        }
    }
}