package com.voteomatic.cryptography.voting;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents the actual content of a vote cast by a voter.
 * This structure should be simple and serializable.
 * The specific content (e.g., candidate ID, choice) depends on the election type.
 */
public class Vote implements Serializable {

    private static final long serialVersionUID = 1L; // For Serializable interface

    // Example content: could be a candidate ID, a ranking, etc.
    private final String selectedOption;

    /**
     * Constructs a Vote object.
     *
     * @param selectedOption The option chosen by the voter (e.g., candidate name/ID). Must not be null.
     */
    public Vote(String selectedOption) {
        Objects.requireNonNull(selectedOption, "Selected option cannot be null");
        this.selectedOption = selectedOption;
    }

    public String getSelectedOption() {
        return selectedOption;
    }

    // It's crucial that the representation used for encryption (e.g., BigInteger)
    // can be deterministically derived from this object.
    // A method like this might be needed:
    // public BigInteger toBigIntegerRepresentation(SomeEncodingScheme scheme) { ... }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Vote vote = (Vote) o;
        return selectedOption.equals(vote.selectedOption);
    }

    @Override
    public int hashCode() {
        return Objects.hash(selectedOption);
    }

    @Override
    public String toString() {
        // Be cautious about logging vote content directly
        return "Vote{selectedOption='[REDACTED]'}";
    }
}