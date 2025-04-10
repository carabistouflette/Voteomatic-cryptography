package com.voteomatic.cryptography.securityutils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

/**
 * A general implementation of the DigitalSignature interface using java.security.Signature.
 * This class can be configured with a specific JCA signature algorithm name (e.g., "SHA256withRSA").
 */
public class DigitalSignatureImpl implements DigitalSignature {

    private final String algorithmName;

    /**
     * Constructs a DigitalSignatureImpl for the specified algorithm.
     *
     * @param algorithmName The standard JCA name of the signature algorithm (e.g., "SHA256withRSA", "SHA512withECDSA").
     *                      Must not be null or empty.
     */
    public DigitalSignatureImpl(String algorithmName) {
        this.algorithmName = Objects.requireNonNull(algorithmName, "Algorithm name cannot be null.");
        if (algorithmName.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm name cannot be empty.");
        }
        // Optional: Check if the algorithm is available at construction time
        try {
            Signature.getInstance(this.algorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Signature algorithm '" + algorithmName + "' is not available.", e);
        }
    }

    @Override
    public byte[] sign(byte[] data, PrivateSigningKey privateKey) throws SecurityUtilException {
        Objects.requireNonNull(data, "Data to sign cannot be null.");
        Objects.requireNonNull(privateKey, "Private signing key cannot be null.");
        if (data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be empty.");
        }

        if (!(privateKey instanceof PrivateSigningKeyImpl)) {
            throw new SecurityUtilException("Unsupported PrivateSigningKey type: " + privateKey.getClass().getName() +
                                            ". Expected PrivateSigningKeyImpl.");
        }

        PrivateKey jcaPrivateKey = ((PrivateSigningKeyImpl) privateKey).getJcaPrivateKey();

        try {
            Signature signatureInstance = Signature.getInstance(this.algorithmName);
            signatureInstance.initSign(jcaPrivateKey);
            signatureInstance.update(data);
            return signatureInstance.sign();
        } catch (NoSuchAlgorithmException e) {
            // Should not happen if checked in constructor, but good practice to handle
            throw new SecurityUtilException("Signature algorithm '" + this.algorithmName + "' not found during signing.", e);
        } catch (InvalidKeyException e) {
            throw new SecurityUtilException("Invalid private key provided for algorithm '" + this.algorithmName + "'.", e);
        } catch (SignatureException e) {
            throw new SecurityUtilException("Error occurred during the signing process.", e);
        } catch (Exception e) {
            // Catch any other unexpected runtime exceptions
            throw new SecurityUtilException("Unexpected error during signing.", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, PublicVerificationKey publicKey) throws SecurityUtilException {
        Objects.requireNonNull(data, "Data to verify cannot be null.");
        Objects.requireNonNull(signature, "Signature cannot be null.");
        Objects.requireNonNull(publicKey, "Public verification key cannot be null.");
        if (data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be empty.");
        }
        if (signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be empty.");
        }

        if (!(publicKey instanceof PublicVerificationKeyImpl)) {
            throw new SecurityUtilException("Unsupported PublicVerificationKey type: " + publicKey.getClass().getName() +
                                            ". Expected PublicVerificationKeyImpl.");
        }

        PublicKey jcaPublicKey = ((PublicVerificationKeyImpl) publicKey).getJcaPublicKey();

        try {
            Signature signatureInstance = Signature.getInstance(this.algorithmName);
            signatureInstance.initVerify(jcaPublicKey);
            signatureInstance.update(data);
            return signatureInstance.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            // Should not happen if checked in constructor
            throw new SecurityUtilException("Signature algorithm '" + this.algorithmName + "' not found during verification.", e);
        } catch (InvalidKeyException e) {
            throw new SecurityUtilException("Invalid public key provided for algorithm '" + this.algorithmName + "'.", e);
        } catch (SignatureException e) {
            // This often indicates a verification failure, but the API contract is to return false.
            // However, it *can* also indicate other errors (like malformed signature).
            // Returning false is generally the expected behavior for a verification failure.
            // Log the exception if debugging is needed, but don't throw SecurityUtilException for a simple mismatch.
            // System.err.println("SignatureException during verify (might be normal verification failure): " + e.getMessage());
            return false;
        } catch (Exception e) {
            // Catch any other unexpected runtime exceptions
            throw new SecurityUtilException("Unexpected error during verification.", e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return this.algorithmName;
    }
}