package com.voteomatic.cryptography.core.elgamal;

import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Implements the ElGamal encryption and decryption scheme.
 * This implementation uses java.math.BigInteger for cryptographic operations.
 */
public class ElGamalCipherImpl implements ElGamalCipher {

    private final SecureRandomGenerator secureRandomGenerator;

    /**
     * Constructs an ElGamalCipherImpl with a secure random generator.
     *
     * @param secureRandomGenerator The generator for creating the ephemeral secret k. Must not be null.
     * @throws IllegalArgumentException if secureRandomGenerator is null.
     */
    public ElGamalCipherImpl(SecureRandomGenerator secureRandomGenerator) {
        Objects.requireNonNull(secureRandomGenerator, "SecureRandomGenerator cannot be null");
        this.secureRandomGenerator = secureRandomGenerator;
    }

    /**
     * Encrypts a message using the provided ElGamal public key.
     *
     * @param publicKey The public key (p, g, y) to use for encryption. Must not be null.
     * @param message   The message to encrypt as a BigInteger. Must not be null.
     *                  The message must be representable within the group defined by p.
     * @return The resulting Ciphertext (c1, c2).
     * @throws IllegalArgumentException if publicKey or message is null.
     * @throws ArithmeticException      if cryptographic computations encounter issues (e.g., invalid parameters).
     */
    @Override
    public Ciphertext encrypt(PublicKey publicKey, BigInteger message) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");

        BigInteger p = publicKey.getP();
        BigInteger g = publicKey.getG();
        BigInteger y = publicKey.getY();

        // Ensure message is less than p (though technically it should be in the group)
        if (message.compareTo(p) >= 0 || message.compareTo(BigInteger.ZERO) < 0) {
            // While ElGamal works mathematically for m=0, it might leak information.
            // Often restricted to m in [1, p-1]. We'll allow 0 for now but could restrict.
             throw new IllegalArgumentException("Message must be non-negative and less than p");
        }

        // Generate ephemeral secret k such that 1 <= k < p-1
        // We generate in [0, p-3] and add 1 to get [1, p-2].
        // p-1 is excluded as g^(p-1) mod p = 1.
        // The range for k is often tied to the group order q if p is a safe prime (p=2q+1),
        // but using p-2 as the upper bound for the base generation is generally safe.
        BigInteger pMinusTwo = p.subtract(BigInteger.TWO);
        if (pMinusTwo.compareTo(BigInteger.ZERO) <= 0) {
             throw new ArithmeticException("Prime p must be greater than 3 for secure random generation range.");
        }

        BigInteger k;
        try {
            // Generate k in the range [1, p-2] inclusive.
            // generateBigInteger(limit) produces a number in [0, limit-1].
            // So, generateBigInteger(p-2) gives [0, p-3]. Adding 1 gives [1, p-2].
            k = secureRandomGenerator.generateBigInteger(pMinusTwo).add(BigInteger.ONE);
        } catch (SecurityUtilException e) {
            // If random generation fails, wrap it in an ArithmeticException as per interface constraints
            throw new ArithmeticException("Failed to generate ephemeral secret k: " + e.getMessage());
        }

        // Calculate c1 = g^k mod p
        BigInteger c1 = g.modPow(k, p);

        // Calculate s = y^k mod p
        BigInteger s = y.modPow(k, p);

        // Calculate c2 = m * s mod p
        BigInteger c2 = message.multiply(s).mod(p);

        return new Ciphertext(c1, c2);
    }

    /**
     * Decrypts a ciphertext using the provided ElGamal private key.
     *
     * @param privateKey The private key (p, x) to use for decryption. Must not be null.
     * @param ciphertext The ciphertext (c1, c2) to decrypt. Must not be null.
     * @return The original message as a BigInteger.
     * @throws IllegalArgumentException if privateKey or ciphertext is null.
     * @throws ArithmeticException      if the modular inverse does not exist or other calculation errors occur.
     */
    @Override
    public BigInteger decrypt(PrivateKey privateKey, Ciphertext ciphertext) {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");

        BigInteger p = privateKey.getP();
        BigInteger x = privateKey.getX();
        BigInteger c1 = ciphertext.getC1();
        BigInteger c2 = ciphertext.getC2();

        // Validate c1 and c2 are within [0, p-1]
        if (c1.compareTo(p) >= 0 || c1.compareTo(BigInteger.ZERO) < 0 ||
            c2.compareTo(p) >= 0 || c2.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Ciphertext components must be non-negative and less than p");
        }


        // Calculate s = c1^x mod p
        BigInteger s = c1.modPow(x, p);

        // Calculate s_inverse = s^(-1) mod p
        BigInteger sInverse;
        try {
            sInverse = s.modInverse(p);
        } catch (ArithmeticException e) {
            // This happens if s is not relatively prime to p.
            // Since p is prime, this only occurs if s = 0 mod p.
            // s = c1^x mod p. If c1 = 0, this could happen.
            // If g^k mod p = 0, this implies p divides g^k, only possible if p divides g (invalid params) or k=0 (not allowed).
            // Wrap the original exception if needed, but the basic constructor is sufficient here.
            throw new ArithmeticException("Failed to compute modular inverse (s = " + s + ", p = " + p + "). Ciphertext might be invalid or parameters incorrect.");
        }

        // Calculate m = c2 * s_inverse mod p
        BigInteger message = c2.multiply(sInverse).mod(p);

        return message;
    }
}