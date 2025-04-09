package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.zkp.Proof; // Assuming a generic Proof interface exists

import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;

/**
 * Represents a vote after it has been encrypted.
 * Contains the ElGamal ciphertext and optionally an associated Zero-Knowledge Proof
 * (e.g., proving the vote is valid without revealing its content).
 */
public class EncryptedVote implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Ciphertext voteCiphertext;
    private final Proof validityProof; // Optional: Proof of vote validity

    /**
     * Constructs an EncryptedVote with ciphertext and proof.
     *
     * @param voteCiphertext The ElGamal ciphertext of the vote. Must not be null.
     * @param validityProof  The ZKP proving the vote's validity. Can be null if no proof is attached.
     */
    public EncryptedVote(Ciphertext voteCiphertext, Proof validityProof) {
        Objects.requireNonNull(voteCiphertext, "Vote ciphertext cannot be null");
        this.voteCiphertext = voteCiphertext;
        this.validityProof = validityProof; // Nullable
    }

    /**
     * Constructs an EncryptedVote with only ciphertext (no proof).
     *
     * @param voteCiphertext The ElGamal ciphertext of the vote. Must not be null.
     */
    public EncryptedVote(Ciphertext voteCiphertext) {
        this(voteCiphertext, null);
    }

    public Ciphertext getVoteCiphertext() {
        return voteCiphertext;
    }

    /**
     * Gets the validity proof, if present.
     *
     * @return An Optional containing the Proof, or Optional.empty() if no proof is attached.
     */
    public Optional<Proof> getValidityProof() {
        return Optional.ofNullable(validityProof);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedVote that = (EncryptedVote) o;
        return voteCiphertext.equals(that.voteCiphertext) && Objects.equals(validityProof, that.validityProof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(voteCiphertext, validityProof);
    }

    @Override
    public String toString() {
        return "EncryptedVote{" +
               "voteCiphertext=" + voteCiphertext +
               ", validityProof=" + (validityProof != null ? "present" : "absent") +
               '}';
    }
}