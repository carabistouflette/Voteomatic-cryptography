package com.voteomatic.cryptography.securityutils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when; // Import Mockito static methods

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito; // Import Mockito

class PublicVerificationKeyImplTest {

  private static PublicKey jcaPublicKey;
  private static final String ALGORITHM = "RSA"; // Example algorithm

  @BeforeAll
  static void setUp() throws NoSuchAlgorithmException {
    // Generate a sample JCA PublicKey for testing
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
    keyGen.initialize(2048); // Example key size
    KeyPair keyPair = keyGen.generateKeyPair();
    jcaPublicKey = keyPair.getPublic();
  }

  @Test
  void constructor_validKey_createsInstance() {
    PublicVerificationKeyImpl verificationKey = new PublicVerificationKeyImpl(jcaPublicKey);
    assertNotNull(verificationKey);
    assertEquals(jcaPublicKey, verificationKey.getJcaPublicKey());
  }

  @Test
  void constructor_nullKey_throwsException() {
    assertThrows(
        NullPointerException.class,
        () -> { // Corrected expected exception
          new PublicVerificationKeyImpl(null);
        });
  }

  @Test
  void getJcaPublicKey_returnsCorrectKey() {
    PublicVerificationKeyImpl verificationKey = new PublicVerificationKeyImpl(jcaPublicKey);
    assertEquals(jcaPublicKey, verificationKey.getJcaPublicKey());
  }

  @Test
  void getAlgorithm_returnsCorrectAlgorithm() {
    PublicVerificationKeyImpl verificationKey = new PublicVerificationKeyImpl(jcaPublicKey);
    assertEquals(ALGORITHM, verificationKey.getAlgorithm());
  }

  @Test
  void getEncoded_returnsCorrectEncoding()
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    PublicVerificationKeyImpl verificationKey = new PublicVerificationKeyImpl(jcaPublicKey);
    byte[] encodedKey = verificationKey.getEncoded();
    assertNotNull(encodedKey);
    assertTrue(encodedKey.length > 0);

    // Verify the encoding by reconstructing the key
    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
    PublicKey reconstructedKey = keyFactory.generatePublic(keySpec);

    assertEquals(jcaPublicKey, reconstructedKey);
  }

  /** Tests that getEncoded returns null if the underlying JCA key's getEncoded returns null. */
  @Test
  void getEncoded_returnsNullWhenUnderlyingKeyEncodingIsNull() {
    // 1. Create a mock JCA PublicKey
    PublicKey mockJcaPublicKey = Mockito.mock(PublicKey.class);

    // 2. Configure the mock to return null for getEncoded()
    when(mockJcaPublicKey.getEncoded()).thenReturn(null);
    // We also need to mock getAlgorithm() as it's called by the constructor indirectly via
    // PublicVerificationKeyImpl constructor
    // (though not strictly necessary for testing getEncoded, it prevents potential
    // NullPointerExceptions if the constructor logic changes)
    // Let's assume it returns some algorithm name.
    when(mockJcaPublicKey.getAlgorithm()).thenReturn("MOCK_ALG");

    // 3. Create the PublicVerificationKeyImpl with the mock
    PublicVerificationKeyImpl verificationKey = new PublicVerificationKeyImpl(mockJcaPublicKey);

    // 4. Call getEncoded() and assert it returns null
    byte[] encoded = verificationKey.getEncoded();
    assertNull(encoded, "getEncoded should return null when the underlying key encoding is null");
  }
}
