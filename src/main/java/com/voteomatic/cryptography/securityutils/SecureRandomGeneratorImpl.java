package com.voteomatic.cryptography.securityutils;

import java.math.BigInteger;
import java.security.SecureRandom;

/** Implementation of SecureRandomGenerator using java.security.SecureRandom. */
public class SecureRandomGeneratorImpl implements SecureRandomGenerator {

  private final SecureRandom secureRandom;

  /** Private constructor using the default SecureRandom instance. */
  private SecureRandomGeneratorImpl() {
    this.secureRandom = new SecureRandom();
  }

  /**
   * Private constructor using a specific SecureRandom instance.
   *
   * @param secureRandom The SecureRandom instance to use. Assumed non-null by factory method.
   */
  private SecureRandomGeneratorImpl(SecureRandom secureRandom) {
    // Null check is performed in the factory method before calling this constructor.
    this.secureRandom = secureRandom;
  }

  /**
   * Creates a SecureRandomGeneratorImpl using the default SecureRandom instance.
   *
   * @return A new SecureRandomGeneratorImpl instance.
   */
  public static SecureRandomGeneratorImpl createDefault() {
    return new SecureRandomGeneratorImpl();
  }

  /**
   * Creates a SecureRandomGeneratorImpl using a specific SecureRandom instance. Useful for testing
   * or specific algorithm requirements.
   *
   * @param secureRandom The SecureRandom instance to use. Must not be null.
   * @return A new SecureRandomGeneratorImpl instance.
   * @throws IllegalArgumentException if secureRandom is null.
   */
  public static SecureRandomGeneratorImpl create(SecureRandom secureRandom) {
    if (secureRandom == null) {
      throw new IllegalArgumentException("SecureRandom instance cannot be null.");
    }
    return new SecureRandomGeneratorImpl(secureRandom);
  }

  @Override
  public byte[] generateBytes(int length) throws SecurityUtilException {
    if (length < 0) {
      throw new SecurityUtilException("Length cannot be negative.");
    }
    if (length > 1_048_576) { // 1MB max
      throw new SecurityUtilException("Requested byte length too large (max 1MB)");
    }
    try {
      byte[] bytes = new byte[length];
      this.secureRandom.nextBytes(bytes);
      return bytes;
    } catch (Exception e) {
      // Catching generic Exception as SecureRandom.nextBytes doesn't declare checked exceptions,
      // but underlying providers might throw runtime exceptions.
      throw new SecurityUtilException("Error generating random bytes.", e);
    }
  }

  @Override
  public BigInteger generateBigInteger(BigInteger limit) throws SecurityUtilException {
    if (limit == null || limit.signum() <= 0) {
      throw new SecurityUtilException("Limit must be positive.");
    }
    try {
      BigInteger randomBigInt;
      do {
        // Generate a random BigInteger with the same bit length as the limit
        randomBigInt = new BigInteger(limit.bitLength(), this.secureRandom);
      } while (randomBigInt.compareTo(limit) >= 0); // Ensure it's less than the limit
      return randomBigInt;
    } catch (Exception e) {
      throw new SecurityUtilException("Error generating random BigInteger within limit.", e);
    }
  }

  @Override
  public BigInteger generateRandomBits(int numBits) throws SecurityUtilException {
    if (numBits < 0) {
      throw new SecurityUtilException("Number of bits cannot be negative.");
    }
    if (numBits > 10_000) { // 10,000 bits max
      throw new SecurityUtilException("Requested bit length too large (max 10,000 bits)");
    }
    try {
      // SecureRandom constructor for BigInteger ensures non-negativity
      return new BigInteger(numBits, this.secureRandom);
    } catch (Exception e) {
      throw new SecurityUtilException("Error generating random BigInteger with specified bits.", e);
    }
  }
}
