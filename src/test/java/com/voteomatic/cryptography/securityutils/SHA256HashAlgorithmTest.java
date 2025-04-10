package com.voteomatic.cryptography.securityutils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Timeout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class SHA256HashAlgorithmTest {

    private SHA256HashAlgorithm hashAlgorithm;
    private Random random;

    @BeforeEach
    void setUp() {
        hashAlgorithm = new SHA256HashAlgorithm();
        random = new Random();
    }

    @Test
    void getAlgorithmName() {
        assertEquals("SHA-256", hashAlgorithm.getAlgorithmName());
    }

    @Test
    void getDigestLength() {
        assertEquals(32, hashAlgorithm.getDigestLength());
    }

    @Test
    void hash_validInput_returnsCorrectHash() throws SecurityUtilException, NoSuchAlgorithmException {
        byte[] input = "test input".getBytes(StandardCharsets.UTF_8);
        byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest(input);
        byte[] actualHash = hashAlgorithm.hash(input);
        assertArrayEquals(expectedHash, actualHash);
    }

    @Test
    void hash_emptyInput_returnsCorrectHash() throws SecurityUtilException, NoSuchAlgorithmException {
        byte[] input = "".getBytes(StandardCharsets.UTF_8);
        byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest(input);
        byte[] actualHash = hashAlgorithm.hash(input);
        assertArrayEquals(expectedHash, actualHash);
    }

    @Test
    void hash_nullInput_throwsException() {
        assertThrows(SecurityUtilException.class, () -> {
            hashAlgorithm.hash(null);
        });
    }

    @Test
    void hash_differentInputTypes_returnsDifferentHashes() throws SecurityUtilException {
        byte[] input1 = "input1".getBytes(StandardCharsets.UTF_8);
        byte[] input2 = "input2".getBytes(StandardCharsets.UTF_8);
        byte[] hash1 = hashAlgorithm.hash(input1);
        byte[] hash2 = hashAlgorithm.hash(input2);
        assertFalse(java.util.Arrays.equals(hash1, hash2));
    }

    @Test
    void hash_collisionResistance_differentInputsSameLength() throws SecurityUtilException {
        byte[] input1 = new byte[100];
        byte[] input2 = new byte[100];
        random.nextBytes(input1);
        random.nextBytes(input2);
        
        byte[] hash1 = hashAlgorithm.hash(input1);
        byte[] hash2 = hashAlgorithm.hash(input2);
        assertFalse(java.util.Arrays.equals(hash1, hash2));
    }

    @Test
    @Timeout(value = 1000, unit = TimeUnit.MILLISECONDS)
    void hash_largeInput_performance() throws SecurityUtilException {
        byte[] largeInput = new byte[10_000_000]; // 10MB input
        random.nextBytes(largeInput);
        hashAlgorithm.hash(largeInput);
    }

    @RepeatedTest(10)
    void hash_consistentOutput_forSameInput() throws SecurityUtilException {
        byte[] input = "consistent input".getBytes(StandardCharsets.UTF_8);
        byte[] hash1 = hashAlgorithm.hash(input);
        byte[] hash2 = hashAlgorithm.hash(input);
        assertArrayEquals(hash1, hash2);
    }

    @Test
    void hash_veryLargeInput_handlesCorrectly() throws SecurityUtilException {
        byte[] veryLargeInput = new byte[100_000_000]; // 100MB input
        random.nextBytes(veryLargeInput);
        byte[] hash = hashAlgorithm.hash(veryLargeInput);
        assertEquals(32, hash.length);
    }

    @Test
    void hash_inputExceedsMaxSize_throwsException() {
        // Test the explicit size check in the hash method.
        // Note: Allocating this array might fail with OutOfMemoryError in constrained environments
        // before our check is reached, but this test aims to verify the logic if allocation succeeds.
        final int maxSize = 100_000_000;
        byte[] oversizedInput = new byte[maxSize + 1]; // Just over the limit

        SecurityUtilException exception = assertThrows(SecurityUtilException.class, () -> {
            hashAlgorithm.hash(oversizedInput);
        }, "Should throw SecurityUtilException for input exceeding max size");

        assertTrue(exception.getMessage().contains("Input data too large"), "Exception message should indicate size limit exceeded");
    }

    @Test
    void hash_noSuchAlgorithm_throwsSecurityUtilException() {
        byte[] input = "test".getBytes(StandardCharsets.UTF_8);
        String invalidAlgorithm = "NonExistentAlgorithm";

        // Use try-with-resources for MockedStatic
        try (MockedStatic<MessageDigest> mockedDigest = Mockito.mockStatic(MessageDigest.class)) {
            // Mock MessageDigest.getInstance to throw NoSuchAlgorithmException
            mockedDigest.when(() -> MessageDigest.getInstance(eq("SHA-256")))
                        .thenThrow(new NoSuchAlgorithmException(invalidAlgorithm + " not found"));

            // Assert that SecurityUtilException is thrown
            SecurityUtilException exception = assertThrows(SecurityUtilException.class, () -> {
                hashAlgorithm.hash(input);
            });

            // Verify the exception message and cause
            assertTrue(exception.getMessage().contains("SHA-256 algorithm not found"));
            assertNotNull(exception.getCause());
            assertTrue(exception.getCause() instanceof NoSuchAlgorithmException);
        }
    }

    @Test
    void hash_digestError_throwsSecurityUtilException() throws NoSuchAlgorithmException {
        byte[] input = "test".getBytes(StandardCharsets.UTF_8);
        MessageDigest mockDigestInstance = mock(MessageDigest.class);
        RuntimeException runtimeException = new RuntimeException("Simulated digest error");

        // Mock the digest method to throw a generic exception
        when(mockDigestInstance.digest(any(byte[].class))).thenThrow(runtimeException);

        // Use try-with-resources for MockedStatic
        try (MockedStatic<MessageDigest> mockedStaticDigest = Mockito.mockStatic(MessageDigest.class)) {
            // Mock MessageDigest.getInstance to return our mocked instance
            mockedStaticDigest.when(() -> MessageDigest.getInstance(eq("SHA-256")))
                              .thenReturn(mockDigestInstance);

            // Assert that SecurityUtilException is thrown
            SecurityUtilException exception = assertThrows(SecurityUtilException.class, () -> {
                hashAlgorithm.hash(input);
            });

            // Verify the exception message and cause
            assertTrue(exception.getMessage().contains("Error computing SHA-256 hash"));
            assertNotNull(exception.getCause());
            assertSame(runtimeException, exception.getCause());
        }
    }
}