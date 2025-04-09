package com.voteomatic.cryptography.securityutils;

/**
 * Interface for digital signature algorithms (signing and verification).
 * Defines a contract for services that create and validate digital signatures.
 */
public interface DigitalSignature {

    /**
     * Creates a digital signature for the given data using the provided private signing key.
     *
     * @param data       The data to be signed. Must not be null.
     * @param privateKey The private key used for signing. Must be compatible with the algorithm implementation.
     * @return The digital signature as a byte array.
     * @throws SecurityUtilException if signing fails (e.g., invalid key, internal algorithm error).
     */
    byte[] sign(byte[] data, PrivateSigningKey privateKey) throws SecurityUtilException;

    /**
     * Verifies a digital signature against the original data using the corresponding public verification key.
     *
     * @param data      The original data that was signed. Must not be null.
     * @param signature The signature to be verified. Must not be null.
     * @param publicKey The public key used for verification. Must correspond to the private key used for signing
     *                  and be compatible with the algorithm implementation.
     * @return {@code true} if the signature is valid for the given data and public key, {@code false} otherwise.
     * @throws SecurityUtilException if verification fails due to an error other than an invalid signature
     *                               (e.g., invalid key, incompatible types, internal algorithm error).
     */
    boolean verify(byte[] data, byte[] signature, PublicVerificationKey publicKey) throws SecurityUtilException;

    /**
     * Gets the standard algorithm name (e.g., "SHA256withRSA", "SHA512withECDSA").
     * Useful for identifying the specific algorithm implementation.
     *
     * @return The standard name of the signature algorithm.
     */
    String getAlgorithmName();
}