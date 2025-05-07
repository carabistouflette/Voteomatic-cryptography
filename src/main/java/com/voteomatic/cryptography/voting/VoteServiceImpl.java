package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.EncryptionResult;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.Proof;
import com.voteomatic.cryptography.core.zkp.Statement;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpProver;
import com.voteomatic.cryptography.core.zkp.ZkpVerifier;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenProof;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenStatement;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenWitness;
import com.voteomatic.cryptography.keymanagement.KeyService;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Implementation of the VoteService interface. */
public class VoteServiceImpl implements VoteService {

  private static final int MAX_VOTES = 10000; // Maximum expected votes for precomputation

  private final ElGamalCipher elGamalCipher;
  private final ZkpProver prover;
  private final ZkpVerifier verifier;
  private final Map<BigInteger, Integer> discreteLogMap; // Precomputed map for g^m -> m

  /**
   * Constructs a VoteServiceImpl with required dependencies and precomputes the discrete log map.
   *
   * @param params The domain parameters (p, q, g) for the election.
   * @param elGamalCipher The ElGamal cipher implementation.
   * @param keyService The key service implementation.
   * @param prover The Zero-Knowledge Proof prover (e.g., DisjunctiveChaumPedersenProver).
   * @param verifier The Zero-Knowledge Proof verifier (e.g., DisjunctiveChaumPedersenVerifier).
   */
  public VoteServiceImpl(
      DomainParameters params,
      ElGamalCipher elGamalCipher,
      KeyService keyService,
      ZkpProver prover,
      ZkpVerifier verifier) {
    Objects.requireNonNull(params, "DomainParameters cannot be null");
    this.elGamalCipher = Objects.requireNonNull(elGamalCipher, "ElGamalCipher cannot be null");
    // Keep null check for constructor parameter, but remove assignment to unused field
    Objects.requireNonNull(keyService, "KeyService cannot be null");
    this.prover = Objects.requireNonNull(prover, "ZkpProver cannot be null");
    this.verifier = Objects.requireNonNull(verifier, "ZkpVerifier cannot be null");

    // Precompute the discrete logarithm map for efficient tallying
    this.discreteLogMap = precomputeDiscreteLogMap(params, MAX_VOTES);

    // Optional: Add checks for prover/verifier types if needed
    // if (!(prover instanceof DisjunctiveChaumPedersenProver)) { ... }
    // if (!(verifier instanceof DisjunctiveChaumPedersenVerifier)) { ... }
  }

  /**
   * Precomputes a map from g^i mod p to i for efficient discrete logarithm lookup during tallying.
   *
   * @param params The domain parameters containing g and p.
   * @param max The maximum value of the exponent i (e.g., MAX_VOTES).
   * @return A map where keys are g^i mod p and values are i.
   */
  private Map<BigInteger, Integer> precomputeDiscreteLogMap(DomainParameters params, int max) {
    BigInteger g = params.getG();
    BigInteger p = params.getP();
    Map<BigInteger, Integer> map = new HashMap<>(max + 1);
    BigInteger gPowI = BigInteger.ONE; // Start with g^0

    for (int i = 0; i <= max; i++) {
      map.put(gPowI, i);
      gPowI = gPowI.multiply(g).mod(p); // Calculate g^(i+1) for the next iteration
    }
    return map;
  }

  @Override
  public EncryptedVote castVote(
      VoterCredentials credentials, Vote vote, PublicKey electionPublicKey) throws VotingException {
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
        throw new VotingException(
            "Invalid vote option: '" + selectedOption + "'. Only 'Yes' or 'No' are allowed.");
      }

      // Basic validation (g^1 and g^0 should always be < p if parameters are valid)
      // This check might be redundant if key generation ensures g < p, but kept for safety.
      if (message.compareTo(p) >= 0) {
        // This case should theoretically not happen with g^1 or g^0 encoding
        throw new VotingException(
            "Encoded vote value is unexpectedly too large for the ElGamal parameters.");
      }

      // Encrypt the encoded vote message and get randomness
      EncryptionResult encryptionResult = elGamalCipher.encrypt(electionPublicKey, message);
      Ciphertext voteCiphertext = encryptionResult.getCiphertext();
      BigInteger randomness = encryptionResult.getRandomness(); // The 'r' value

      // Determine vote index v (0 for No, 1 for Yes) and possible messages m0, m1
      int voteIndex;
      BigInteger m0 = BigInteger.ONE; // g^0
      BigInteger m1 = g; // g^1
      if ("Yes".equalsIgnoreCase(selectedOption)) {
        voteIndex = 1;
      } else { // Must be "No" due to earlier validation
        voteIndex = 0;
      }

      // Create ZKP Statement and Witness
      DisjunctiveChaumPedersenStatement statement =
          DisjunctiveChaumPedersenStatement.create(electionPublicKey, voteCiphertext, m0, m1);
      DisjunctiveChaumPedersenWitness witness =
          DisjunctiveChaumPedersenWitness.create(randomness, voteIndex);

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
  public BigInteger tallyVotes(List<EncryptedVote> encryptedVotes, PrivateKey electionPrivateKey)
      throws VotingException {
    Objects.requireNonNull(encryptedVotes, "Encrypted votes list cannot be null");
    Objects.requireNonNull(electionPrivateKey, "Election PrivateKey cannot be null");

    if (encryptedVotes.isEmpty()) {
      // If there are no votes, the tally k is 0.
      return BigInteger.ZERO;
    }

    DomainParameters params = electionPrivateKey.getParams();
    Objects.requireNonNull(params, "DomainParameters cannot be null in PrivateKey");
    BigInteger p = params.getP(); // Get modulus from private key's DomainParameters

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
        throw new VotingException(
            "Error multiplying ciphertexts during tally: " + e.getMessage(), e);
      }
    }

    try {
      // Decrypt the final accumulated ciphertext
      BigInteger decryptedResultGk =
          elGamalCipher.decrypt(electionPrivateKey, accumulatedCiphertext); // This is g^k mod p

      // Find k by solving the discrete logarithm g^k = decryptedResultGk (mod p)
      // Since k represents the count of "Yes" votes (encoded as g^1),
      // we can find it by trial exponentiation for small k.
      // Look up the tally count (k) using the precomputed discrete log map
      Integer voteCount = this.discreteLogMap.get(decryptedResultGk);

      if (voteCount == null) {
        // If the decrypted result is not in the map, it's either invalid
        // or exceeds the precomputed maximum (MAX_VOTES).
        throw new VotingException(
            "Could not determine the vote tally (k) from the decrypted result. "
                + "The result ("
                + decryptedResultGk
                + ") was not found in the precomputed map. "
                + "It might be invalid or exceed the maximum precomputed tally of "
                + MAX_VOTES
                + ".");
      }

      return BigInteger.valueOf(voteCount); // Return the tally k

    } catch (Exception e) {
      // Wrap decryption or tally interpretation error
      throw new VotingException(
          "Error during final tally decryption or interpretation: " + e.getMessage(), e);
    }
  }

  @Override
  public boolean verifyVote(EncryptedVote encryptedVote, Statement statement, Proof proof)
      throws VotingException, ZkpException {
    // EncryptedVote parameter is currently unused but kept for signature compatibility.
    // A better design might reconstruct the statement internally using the public key.
    Objects.requireNonNull(statement, "Statement cannot be null for verification");
    Objects.requireNonNull(proof, "Proof cannot be null for verification");

    // Check if the provided statement and proof are of the expected DisjunctiveChaumPedersen types.
    if (!(statement instanceof DisjunctiveChaumPedersenStatement)) {
      throw new IllegalArgumentException(
          "Statement must be an instance of DisjunctiveChaumPedersenStatement for verification.");
      // return false; // Alternatively, just return false if type mismatch means invalid proof
    }
    if (!(proof instanceof DisjunctiveChaumPedersenProof)) {
      throw new IllegalArgumentException(
          "Proof must be an instance of DisjunctiveChaumPedersenProof for verification.");
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
