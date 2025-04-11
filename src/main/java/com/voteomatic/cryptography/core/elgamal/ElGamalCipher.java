package com.voteomatic.cryptography.core.elgamal;

import java.math.BigInteger;

/**
 * Interface for ElGamal encryption and decryption operations.
 * Defines the contract for handling the core cryptographic functions of the ElGamal scheme.
 */
public interface ElGamalCipher {

    /**
     * Encrypts a message using the recipient's ElGamal public key.
     *
     * @param publicKey The recipient's public key.
     * @param message   The message to encrypt (represented as a BigInteger).
     * @return An EncryptionResult containing the Ciphertext and the randomness used.
     * @throws IllegalArgumentException if the key or message is invalid.
     */
    EncryptionResult encrypt(PublicKey publicKey, BigInteger message);

    /**
     * Decrypts a ciphertext using the recipient's ElGamal private key.
     *
     * @param privateKey The recipient's private key.
     * @param ciphertext The ciphertext to decrypt.
     * @return The original message (represented as a BigInteger).
     * @throws IllegalArgumentException if the key or ciphertext is invalid or decryption fails.
     */
    BigInteger decrypt(PrivateKey privateKey, Ciphertext ciphertext);
}