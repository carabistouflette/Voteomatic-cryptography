package com.voteomatic.cryptography.core.zkp;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecurityUtilException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/** Utility class for computing challenges in Zero-Knowledge Proofs. */
public final class ZkpChallengeUtils {

  // Private constructor to prevent instantiation
  private ZkpChallengeUtils() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Computes the challenge for a Schnorr proof. c = H(p || q || g || y || t)
   *
   * @param params Domain parameters (p, q, g).
   * @param publicKey Public key (y).
   * @param commitment Commitment (t).
   * @param hashAlgorithm Hash algorithm to use.
   * @return The computed challenge as a positive BigInteger.
   * @throws ZkpException if serialization fails.
   * @throws SecurityUtilException if hashing fails.
   */
  public static BigInteger computeSchnorrChallenge(
      DomainParameters params,
      PublicKey publicKey,
      BigInteger commitment,
      HashAlgorithm hashAlgorithm)
      throws ZkpException, SecurityUtilException {
    // Concatenate canonical byte representations with length prefixes for hashing.
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      writeBigIntegerWithLength(baos, params.getP());
      writeBigIntegerWithLength(baos, params.getQ());
      writeBigIntegerWithLength(baos, params.getG());
      writeBigIntegerWithLength(baos, publicKey.getY());
      writeBigIntegerWithLength(baos, commitment);
      byte[] dataToHash = baos.toByteArray();
      byte[] hashBytes = hashAlgorithm.hash(dataToHash);
      // Convert hash bytes to a positive BigInteger
      return new BigInteger(1, hashBytes);
    } catch (IOException e) {
      // Should not happen with ByteArrayOutputStream
      throw new ZkpException("Error during byte array serialization for Schnorr challenge", e);
    }
    // SecurityUtilException from hashAlgorithm.hash() is now propagated
  }

  /**
   * Writes a BigInteger to the output stream, prefixed with its 4-byte big-endian length.
   *
   * @param baos The output stream.
   * @param val The BigInteger to write.
   * @throws IOException if an I/O error occurs.
   */
  private static void writeBigIntegerWithLength(ByteArrayOutputStream baos, BigInteger val)
      throws IOException {
    byte[] bytes = val.toByteArray();
    int len = bytes.length;
    // Write length as 4-byte big-endian integer
    baos.write((len >> 24) & 0xFF);
    baos.write((len >> 16) & 0xFF);
    baos.write((len >> 8) & 0xFF);
    baos.write(len & 0xFF);
    // Write the actual bytes
    baos.write(bytes);
  }

  /**
   * Computes the challenge for a Disjunctive Chaum-Pedersen proof. c = H(p || g || h || c1 || c2 ||
   * m0 || m1 || a0 || b0 || a1 || b1) mod q
   *
   * @param statement The public statement containing p, g, q, h, c1, c2, m0, m1.
   * @param commitmentA0 Commitment a0.
   * @param commitmentB0 Commitment b0.
   * @param commitmentA1 Commitment a1.
   * @param commitmentB1 Commitment b1.
   * @param hashAlgorithm Hash algorithm to use.
   * @return The computed challenge as a positive BigInteger, reduced modulo q.
   * @throws ZkpException if serialization fails.
   * @throws SecurityUtilException if hashing fails.
   */
  public static BigInteger computeDisjunctiveChaumPedersenChallenge(
      DisjunctiveChaumPedersenStatement statement,
      BigInteger commitmentA0,
      BigInteger commitmentB0,
      BigInteger commitmentA1,
      BigInteger commitmentB1,
      HashAlgorithm hashAlgorithm)
      throws ZkpException, SecurityUtilException {

    DomainParameters params = statement.getParams();
    BigInteger p = params.getP();
    BigInteger g = params.getG();
    BigInteger q = params.getQ();
    BigInteger h = statement.getH();
    BigInteger c1 = statement.getC1();
    BigInteger c2 = statement.getC2();
    BigInteger m0 = statement.getM0();
    BigInteger m1 = statement.getM1();

    // Serialize inputs using length-prefixing for unambiguous hashing
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      writeBigIntegerWithLength(baos, p);
      writeBigIntegerWithLength(baos, g);
      writeBigIntegerWithLength(baos, h);
      writeBigIntegerWithLength(baos, c1);
      writeBigIntegerWithLength(baos, c2);
      writeBigIntegerWithLength(baos, m0);
      writeBigIntegerWithLength(baos, m1);
      writeBigIntegerWithLength(baos, commitmentA0);
      writeBigIntegerWithLength(baos, commitmentB0);
      writeBigIntegerWithLength(baos, commitmentA1);
      writeBigIntegerWithLength(baos, commitmentB1);

      byte[] inputBytes = baos.toByteArray();
      byte[] hash = hashAlgorithm.hash(inputBytes);
      BigInteger challenge = new BigInteger(1, hash); // Ensure positive BigInteger

      // Reduce the challenge modulo q
      return challenge.mod(q);

    } catch (IOException e) {
      // Should not happen with ByteArrayOutputStream
      throw new ZkpException(
          "Error during byte array serialization for Disjunctive Chaum-Pedersen challenge", e);
    }
    // SecurityUtilException from hashAlgorithm.hash() is now propagated
  }
}
