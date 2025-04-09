package com.voteomatic.cryptography.securityutils;

import java.math.BigInteger;

/**
 * Interface for generating cryptographically secure random numbers and bytes.
 * Defines a contract for sources of randomness suitable for cryptographic operations
 * like key generation, nonces, and padding. Implementations should use a
 * Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
 */
public interface SecureRandomGenerator {

    /**
     * Generates a specified number of secure random bytes.
     *
     * @param length The number of bytes to generate. Must be non-negative.
     * @return A byte array containing the generated random bytes.
     * @throws SecurityUtilException if random byte generation fails.
     */
    byte[] generateBytes(int length) throws SecurityUtilException;

    /**
     * Generates a secure random BigInteger that is uniformly distributed in the range
     * 0 to (limit - 1), inclusive.
     *
     * @param limit The upper bound (exclusive). Must be positive.
     * @return A randomly generated BigInteger within the specified range.
     * @throws SecurityUtilException if random BigInteger generation fails.
     */
    BigInteger generateBigInteger(BigInteger limit) throws SecurityUtilException;

    /**
     * Generates a secure random BigInteger with the specified number of bits.
     * The probability that a BigInteger constructed this way is prime is negligible,
     * but it's useful for generating random exponents or blinding factors.
     *
     * @param numBits The number of bits for the random BigInteger. Must be non-negative.
     * @return A randomly generated BigInteger of the specified bit length.
     * @throws SecurityUtilException if random BigInteger generation fails.
     */
    BigInteger generateRandomBits(int numBits) throws SecurityUtilException;

}