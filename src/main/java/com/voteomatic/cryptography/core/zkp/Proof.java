package com.voteomatic.cryptography.core.zkp;

/**
 * Marker interface for a generated Zero-Knowledge Proof.
 * Concrete implementations will define the specific data comprising the proof
 * generated by a particular ZKP system (e.g., commitments, challenges, responses).
 */
public interface Proof {
    // Marker interface - no methods required at this base level.
    // Implementations will contain the actual proof data.
}