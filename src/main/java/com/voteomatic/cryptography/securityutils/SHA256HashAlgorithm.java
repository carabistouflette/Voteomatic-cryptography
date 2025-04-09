package com.voteomatic.cryptography.securityutils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of HashAlgorithm using the SHA-256 algorithm.
 */
public class SHA256HashAlgorithm implements HashAlgorithm {

    private static final String ALGORITHM_NAME = "SHA-256";
    private static final int DIGEST_LENGTH_BYTES = 32; // 256 bits / 8 bits/byte

    @Override
    public byte[] hash(byte[] data) throws SecurityUtilException {
        if (data == null) {
            throw new SecurityUtilException("Data to be hashed cannot be null.");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM_NAME);
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            // This should ideally not happen if SHA-256 is supported by the JRE
            throw new SecurityUtilException(ALGORITHM_NAME + " algorithm not found.", e);
        } catch (Exception e) {
            // Catch unexpected runtime errors during hashing
            throw new SecurityUtilException("Error computing " + ALGORITHM_NAME + " hash.", e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    @Override
    public int getDigestLength() {
        // Alternatively, could get this dynamically: MessageDigest.getInstance(ALGORITHM_NAME).getDigestLength();
        // But using a constant is slightly more efficient if the length is fixed and known.
        return DIGEST_LENGTH_BYTES;
    }
}