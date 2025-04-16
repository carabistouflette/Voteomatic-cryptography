package com.voteomatic.cryptography.core.zkp;

/**
 * Marker interface for a public statement in a Zero-Knowledge Proof. Concrete implementations will
 * define the specific data comprising the statement for a particular proof system (e.g., proving
 * knowledge of a discrete logarithm).
 */
public interface Statement {
  // Marker interface - no methods required at this base level.
  // Implementations will contain the actual statement data.
}
