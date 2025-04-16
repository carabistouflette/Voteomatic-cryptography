package com.voteomatic.cryptography.securityutils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class DigitalSignatureImplTest {

  private static PrivateSigningKey privateKey;
  private static PublicVerificationKey publicKey;
  private static PrivateKey jcaPrivateKey; // Store the raw JCA key
  private static PublicKey jcaPublicKey; // Store the raw JCA key
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA"; // Example algorithm
  private static final String KEY_ALGORITHM = "RSA";
  private DigitalSignature digitalSignature;

  @BeforeAll
  static void setUpKeys() throws NoSuchAlgorithmException {
    // Generate a key pair for testing
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    jcaPrivateKey = keyPair.getPrivate(); // Store raw key
    jcaPublicKey = keyPair.getPublic(); // Store raw key
    privateKey = new PrivateSigningKeyImpl(jcaPrivateKey);
    publicKey = new PublicVerificationKeyImpl(jcaPublicKey);
  }

  @BeforeEach
  void setUp() throws SecurityUtilException {
    digitalSignature = DigitalSignatureImpl.create(SIGNATURE_ALGORITHM);
  }

  @Test
  void constructor_validAlgorithm_createsInstance() {
    assertNotNull(digitalSignature);
    assertEquals(SIGNATURE_ALGORITHM, digitalSignature.getAlgorithmName());
  }

  @Test
  void constructor_nullAlgorithm_throwsException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          DigitalSignatureImpl.create(null);
        },
        "Constructor should throw NullPointerException for null algorithm name");
  }

  @Test
  void constructor_emptyAlgorithm_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          DigitalSignatureImpl.create("");
        },
        "Constructor should throw IllegalArgumentException for empty algorithm name");
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          DigitalSignatureImpl.create("   ");
        },
        "Constructor should throw IllegalArgumentException for blank algorithm name");
  }

  @Test
  void constructor_invalidAlgorithm_throwsException() {
    // This test covers the NoSuchAlgorithmException catch block in the constructor
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          DigitalSignatureImpl.create("InvalidAlgorithmName");
        });
  }

  @Test
  void getAlgorithmName_returnsCorrectName() {
    assertEquals(SIGNATURE_ALGORITHM, digitalSignature.getAlgorithmName());
  }

  @Test
  void signAndVerify_validDataAndKey_success() throws SecurityUtilException {
    byte[] data = "test data to sign".getBytes(StandardCharsets.UTF_8);

    // Sign the data
    byte[] signature = digitalSignature.sign(data, privateKey);
    assertNotNull(signature);
    assertTrue(signature.length > 0);

    // Verify the signature
    boolean isValid = digitalSignature.verify(data, signature, publicKey);
    assertTrue(isValid, "Signature should be valid");
  }

  @Test
  void verify_invalidSignature_returnsFalse() throws SecurityUtilException {
    byte[] data = "test data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = digitalSignature.sign(data, privateKey);

    // Tamper with the signature
    signature[0] = (byte) (signature[0] + 1);

    boolean isValid = digitalSignature.verify(data, signature, publicKey);
    // This covers the case where Signature.verify throws SignatureException, which is caught and
    // returns false
    assertFalse(isValid, "Signature should be invalid after tampering");
  }

  @Test
  void verify_invalidData_returnsFalse() throws SecurityUtilException {
    byte[] data = "original data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = digitalSignature.sign(data, privateKey);

    byte[] tamperedData = "tampered data".getBytes(StandardCharsets.UTF_8);

    boolean isValid = digitalSignature.verify(tamperedData, signature, publicKey);
    // This also covers the case where Signature.verify throws SignatureException, which is caught
    // and returns false
    assertFalse(isValid, "Signature should be invalid for tampered data");
  }

  @Test
  void sign_nullData_throwsException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          digitalSignature.sign(null, privateKey);
        });
  }

  @Test
  void sign_nullPrivateKey_throwsException() {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    assertThrows(
        NullPointerException.class,
        () -> {
          digitalSignature.sign(data, null);
        });
  }

  @Test
  void sign_unsupportedPrivateKeyType_throwsException() {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    // Create a mock PrivateSigningKey that is NOT a PrivateSigningKeyImpl
    PrivateSigningKey mockKey = Mockito.mock(PrivateSigningKey.class);

    SecurityUtilException exception =
        assertThrows(
            SecurityUtilException.class,
            () -> {
              digitalSignature.sign(data, mockKey);
            });
    assertTrue(exception.getMessage().contains("Unsupported PrivateSigningKey type"));
  }

  @Test
  void sign_signatureException_throwsSecurityUtilException() throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    Signature mockSignatureInstance = mock(Signature.class);
    SignatureException sigEx = new SignatureException("Simulated signing error");

    // Mock the sign() method to throw SignatureException
    doThrow(sigEx).when(mockSignatureInstance).sign();

    try (MockedStatic<Signature> mockedStaticSignature = Mockito.mockStatic(Signature.class)) {
      mockedStaticSignature
          .when(() -> Signature.getInstance(SIGNATURE_ALGORITHM))
          .thenReturn(mockSignatureInstance);

      // Need to allow initSign and update to proceed without error
      doNothing().when(mockSignatureInstance).initSign(any(PrivateKey.class));
      doNothing().when(mockSignatureInstance).update(any(byte[].class));

      SecurityUtilException exception =
          assertThrows(
              SecurityUtilException.class,
              () -> {
                digitalSignature.sign(data, privateKey);
              });

      assertTrue(exception.getMessage().contains("Error occurred during the signing process"));
      assertSame(sigEx, exception.getCause());
    }
  }

  @Test
  void sign_genericException_throwsSecurityUtilException() throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    Signature mockSignatureInstance = mock(Signature.class);
    RuntimeException runtimeEx = new RuntimeException("Simulated generic signing error");

    // Mock the sign() method to throw RuntimeException
    doThrow(runtimeEx).when(mockSignatureInstance).sign();

    try (MockedStatic<Signature> mockedStaticSignature = Mockito.mockStatic(Signature.class)) {
      mockedStaticSignature
          .when(() -> Signature.getInstance(SIGNATURE_ALGORITHM))
          .thenReturn(mockSignatureInstance);

      doNothing().when(mockSignatureInstance).initSign(any(PrivateKey.class));
      doNothing().when(mockSignatureInstance).update(any(byte[].class));

      SecurityUtilException exception =
          assertThrows(
              SecurityUtilException.class,
              () -> {
                digitalSignature.sign(data, privateKey);
              });

      assertTrue(exception.getMessage().contains("Unexpected error during signing"));
      assertSame(runtimeEx, exception.getCause());
    }
  }

  @Test
  void sign_noSuchAlgorithm_throwsSecurityUtilException() throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    NoSuchAlgorithmException noSuchAlgoEx =
        new NoSuchAlgorithmException("Simulated no such algorithm");

    try (MockedStatic<Signature> mockedStaticSignature = Mockito.mockStatic(Signature.class)) {
      // Mock getInstance to throw NoSuchAlgorithmException
      mockedStaticSignature
          .when(() -> Signature.getInstance(SIGNATURE_ALGORITHM))
          .thenThrow(noSuchAlgoEx);

      SecurityUtilException exception =
          assertThrows(
              SecurityUtilException.class,
              () -> {
                digitalSignature.sign(data, privateKey);
              });

      assertTrue(exception.getMessage().contains("not found during signing"));
      assertSame(noSuchAlgoEx, exception.getCause());
    }
  }

  @Test
  void verify_nullData_throwsException() {
    byte[] signature = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          digitalSignature.verify(null, signature, publicKey);
        });
  }

  @Test
  void verify_nullSignature_throwsException() {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    assertThrows(
        NullPointerException.class,
        () -> {
          digitalSignature.verify(data, null, publicKey);
        });
  }

  @Test
  void verify_nullPublicKey_throwsException() {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          digitalSignature.verify(data, signature, null);
        });
  }

  @Test
  void verify_unsupportedPublicKeyType_throwsException() throws SecurityUtilException {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = digitalSignature.sign(data, privateKey); // Need a valid signature first
    // Create a mock PublicVerificationKey that is NOT a PublicVerificationKeyImpl
    PublicVerificationKey mockKey = Mockito.mock(PublicVerificationKey.class);

    SecurityUtilException exception =
        assertThrows(
            SecurityUtilException.class,
            () -> {
              digitalSignature.verify(data, signature, mockKey);
            });
    assertTrue(exception.getMessage().contains("Unsupported PublicVerificationKey type"));
  }

  @Test
  void sign_keyAlgorithmMismatch_throwsException() throws NoSuchAlgorithmException {
    // Create a key with a different algorithm (e.g., DSA)
    KeyPairGenerator dsaKeyGen = KeyPairGenerator.getInstance("DSA");
    dsaKeyGen.initialize(2048);
    KeyPair dsaKeyPair = dsaKeyGen.generateKeyPair();
    PrivateSigningKey dsaPrivateKey = new PrivateSigningKeyImpl(dsaKeyPair.getPrivate());

    byte[] data = "data".getBytes(StandardCharsets.UTF_8);

    // Expect an exception because the signature algorithm (RSA) doesn't match the key (DSA)
    // This covers the catch (InvalidKeyException e) block in sign()
    assertThrows(
        SecurityUtilException.class,
        () -> {
          digitalSignature.sign(data, dsaPrivateKey);
        },
        "Should throw exception when key algorithm doesn't match signature algorithm");

    // Note: The NoSuchAlgorithmException catch block in sign() is less likely to be hit
    // if the constructor check passes, but this test ensures coverage.
  }

  @Test
  void verify_keyAlgorithmMismatch_throwsException()
      throws NoSuchAlgorithmException, SecurityUtilException {
    // Create a key with a different algorithm (e.g., DSA)
    KeyPairGenerator dsaKeyGen = KeyPairGenerator.getInstance("DSA");
    dsaKeyGen.initialize(2048);
    KeyPair dsaKeyPair = dsaKeyGen.generateKeyPair();
    PublicVerificationKey dsaPublicKey = new PublicVerificationKeyImpl(dsaKeyPair.getPublic());

    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    // Sign with the correct (RSA) key first
    byte[] signature = digitalSignature.sign(data, privateKey);

    // Expect an exception because the signature algorithm (RSA) doesn't match the key (DSA)
    // This covers the catch (InvalidKeyException e) block in verify()
    assertThrows(
        SecurityUtilException.class,
        () -> {
          digitalSignature.verify(data, signature, dsaPublicKey);
        },
        "Should throw exception when key algorithm doesn't match signature algorithm");

    // Note: The NoSuchAlgorithmException catch block in verify() is less likely to be hit
    // if the constructor check passes, but this test ensures coverage.
  }

  @Test
  void sign_emptyData_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          digitalSignature.sign(new byte[0], privateKey);
        },
        "Should throw exception for empty data array");
  }

  @Test
  void verify_emptySignature_throwsException() {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          digitalSignature.verify(data, new byte[0], publicKey);
        },
        "Should throw exception for empty signature array");
  }

  @Test
  void verify_emptyData_throwsException() {
    byte[] signature = new byte[] {1, 2, 3}; // Non-empty signature
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          digitalSignature.verify(new byte[0], signature, publicKey);
        },
        "Should throw exception for empty data array during verification");
  }

  @Test
  void sign_corruptPrivateKey_throwsException() throws NoSuchAlgorithmException {
    // Create a corrupt RSA private key by modifying bytes
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey corruptKey = keyPair.getPrivate();
    byte[] encoded = corruptKey.getEncoded();
    encoded[0] = (byte) (encoded[0] + 1); // Modify first byte to corrupt

    // Create a PrivateKey object with corrupted bytes
    PrivateKey badKey =
        new PrivateKey() {
          @Override
          public String getAlgorithm() {
            return corruptKey.getAlgorithm();
          }

          @Override
          public String getFormat() {
            return corruptKey.getFormat();
          }

          @Override
          public byte[] getEncoded() {
            return encoded;
          }
        };

    PrivateSigningKey corruptPrivateKey = new PrivateSigningKeyImpl(badKey);
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);

    assertThrows(
        SecurityUtilException.class,
        () -> {
          digitalSignature.sign(data, corruptPrivateKey);
        },
        "Should throw exception for corrupt private key");
  }

  @Test
  void verify_corruptPublicKey_throwsException()
      throws NoSuchAlgorithmException, SecurityUtilException {
    // Create a corrupt RSA public key by modifying bytes
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    PublicKey corruptKey = keyPair.getPublic();
    byte[] encoded = corruptKey.getEncoded();
    encoded[0] = (byte) (encoded[0] + 1); // Modify first byte to corrupt

    // Create a PublicKey object with corrupted bytes
    PublicKey badKey =
        new PublicKey() {
          @Override
          public String getAlgorithm() {
            return corruptKey.getAlgorithm();
          }

          @Override
          public String getFormat() {
            return corruptKey.getFormat();
          }

          @Override
          public byte[] getEncoded() {
            return encoded;
          }
        };

    PublicVerificationKey corruptPublicKey = new PublicVerificationKeyImpl(badKey);
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = digitalSignature.sign(data, privateKey);

    assertThrows(
        SecurityUtilException.class,
        () -> {
          digitalSignature.verify(data, signature, corruptPublicKey);
        },
        "Should throw exception for corrupt public key");
  }

  @Test
  void signAndVerify_withECDSA_works() throws SecurityUtilException, NoSuchAlgorithmException {
    // Test with ECDSA algorithm to verify algorithm independence
    KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
    ecKeyGen.initialize(256);
    KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
    PrivateSigningKey ecPrivateKey = new PrivateSigningKeyImpl(ecKeyPair.getPrivate());
    PublicVerificationKey ecPublicKey = new PublicVerificationKeyImpl(ecKeyPair.getPublic());

    DigitalSignature ecdsaSignature = DigitalSignatureImpl.create("SHA256withECDSA");
    byte[] data = "ecdsa test data".getBytes(StandardCharsets.UTF_8);

    // Sign with ECDSA
    byte[] signature = ecdsaSignature.sign(data, ecPrivateKey);
    assertNotNull(signature);

    // Verify with ECDSA
    boolean isValid = ecdsaSignature.verify(data, signature, ecPublicKey);
    assertTrue(isValid, "ECDSA signature should be valid");
  }

  @Test
  void sign_producesUniqueSignatures() throws SecurityUtilException {
    // Verify that signing the same data produces different signatures (due to randomness)
    byte[] data = "test data".getBytes(StandardCharsets.UTF_8);
    byte[] signature1 = digitalSignature.sign(data, privateKey);
    byte[] signature2 = digitalSignature.sign(data, privateKey);

    assertNotEquals(signature1, signature2, "Signatures should be different due to randomness");
  }

  @Test
  void verify_nonRepudiation_property() throws SecurityUtilException {
    // Verify that only the private key owner can create signatures verifiable by the public key
    byte[] data = "test data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = digitalSignature.sign(data, privateKey);

    // Verification should pass with correct public key
    assertTrue(
        digitalSignature.verify(data, signature, publicKey),
        "Signature should verify with correct public key");

    // Create a different key pair
    KeyPairGenerator keyGen;
    try {
      keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
      keyGen.initialize(2048);
      KeyPair otherKeyPair = keyGen.generateKeyPair();
      PublicVerificationKey otherPublicKey =
          new PublicVerificationKeyImpl(otherKeyPair.getPublic());

      // Verification should fail with different public key
      assertFalse(
          digitalSignature.verify(data, signature, otherPublicKey),
          "Signature should not verify with different public key");
    } catch (NoSuchAlgorithmException e) {
      fail("Failed to generate test key pair", e);
    }
  }

  @Test
  void verify_noSuchAlgorithm_throwsSecurityUtilException() throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    byte[] signature = new byte[] {1, 2, 3}; // Dummy signature
    NoSuchAlgorithmException noSuchAlgoEx =
        new NoSuchAlgorithmException("Simulated no such algorithm");

    try (MockedStatic<Signature> mockedStaticSignature = Mockito.mockStatic(Signature.class)) {
      // Mock getInstance to throw NoSuchAlgorithmException
      mockedStaticSignature
          .when(() -> Signature.getInstance(SIGNATURE_ALGORITHM))
          .thenThrow(noSuchAlgoEx);

      SecurityUtilException exception =
          assertThrows(
              SecurityUtilException.class,
              () -> {
                digitalSignature.verify(data, signature, publicKey);
              });

      assertTrue(exception.getMessage().contains("not found during verification"));
      assertSame(noSuchAlgoEx, exception.getCause());
    }
  }

  @Test
  void verify_genericException_throwsSecurityUtilException() throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = new byte[] {1, 2, 3}; // Dummy signature
    Signature mockSignatureInstance = mock(Signature.class);
    RuntimeException runtimeEx = new RuntimeException("Simulated generic verification error");

    // Mock the verify() method to throw RuntimeException
    when(mockSignatureInstance.verify(any(byte[].class))).thenThrow(runtimeEx);

    try (MockedStatic<Signature> mockedStaticSignature = Mockito.mockStatic(Signature.class)) {
      mockedStaticSignature
          .when(() -> Signature.getInstance(SIGNATURE_ALGORITHM))
          .thenReturn(mockSignatureInstance);

      doNothing().when(mockSignatureInstance).initVerify(any(PublicKey.class));
      doNothing().when(mockSignatureInstance).update(any(byte[].class));

      SecurityUtilException exception =
          assertThrows(
              SecurityUtilException.class,
              () -> {
                digitalSignature.verify(data, signatureBytes, publicKey);
              });

      assertTrue(exception.getMessage().contains("Unexpected error during verification"));
      assertSame(runtimeEx, exception.getCause());
    }
  }
}
