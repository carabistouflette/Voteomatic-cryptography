package com.voteomatic.cryptography.voting;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents the credentials used by a voter to authenticate themselves.
 * NOTE: This is a simplified placeholder. A real system requires a secure
 * authentication mechanism (e.g., tokens, certificates, external IdP integration).
 * This class should NOT contain sensitive information like passwords directly.
 */
public class VoterCredentials implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String voterId;
    // Potentially add authentication tokens or references here in a real system.

    /**
     * Constructs VoterCredentials.
     *
     * @param voterId A unique identifier for the voter. Must not be null.
     */
    public VoterCredentials(String voterId) {
        Objects.requireNonNull(voterId, "Voter ID cannot be null");
        this.voterId = voterId;
    }

    public String getVoterId() {
        return voterId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VoterCredentials that = (VoterCredentials) o;
        return voterId.equals(that.voterId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(voterId);
    }

    @Override
    public String toString() {
        return "VoterCredentials{" +
               "voterId='" + voterId + '\'' +
               '}';
    }
}