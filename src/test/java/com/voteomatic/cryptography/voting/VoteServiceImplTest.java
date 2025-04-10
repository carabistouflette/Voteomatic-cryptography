package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.SchnorrProof;
import com.voteomatic.cryptography.core.zkp.SchnorrProver;
import com.voteomatic.cryptography.core.zkp.*; // Import all ZKP classes
import com.voteomatic.cryptography.keymanagement.KeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets; // Needed for vote encoding

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VoteServiceImplTest {

    @Mock
    private ElGamalCipher elGamalCipher;

    @Mock
    private KeyService keyService; // Although not directly used in methods, it's a dependency

    @Mock
    private SchnorrProver schnorrProver; // Dependency for potential future proof generation

    @Mock
    private SchnorrVerifier schnorrVerifier;

    @InjectMocks
    private VoteServiceImpl voteService;

    // Test Data - Initialize as needed in tests or @BeforeEach
    private Vote sampleVote;
    // Removed voteWithNullOption from fields to avoid NPE in setUp
    private Vote voteWithEmptyOption;
    private VoterCredentials sampleCredentials;
    private PublicKey samplePublicKey;
    private PrivateKey samplePrivateKey; // Needed for tallying
    private Ciphertext mockCiphertext1;
    private Ciphertext mockCiphertext2;
    private SchnorrStatement mockStatement; // Keep as specific type for clarity if needed
    private SchnorrProof mockProof; // Use the specific type for mocking SchnorrVerifier
    private BigInteger p; // Prime modulus from public key

    @BeforeEach
    void setUp() {
        // Initialize common test data
        // Use larger ElGamal parameters suitable for vote encoding
        // Example 128-bit prime and generator g=2
        p = new BigInteger("340282366920938463463374607431768211507"); // 128-bit prime
        BigInteger g = new BigInteger("2");  // Common generator candidate
        BigInteger x = new BigInteger("198765432109876543210987654321"); // Example private key < p
        BigInteger y = g.modPow(x, p); // y = g^x mod p

        samplePublicKey = new PublicKey(p, g, y);
        samplePrivateKey = new PrivateKey(p, g, x); // Use the same x as above
        sampleVote = new Vote("candidateA");
        // voteWithNullOption = new Vote(null); // Moved instantiation to specific test
        voteWithEmptyOption = new Vote("");
        sampleCredentials = new VoterCredentials("voter123"); // Correct constructor

        // Mock Ciphertexts (can be simple mocks or real objects with mock data)
        mockCiphertext1 = mock(Ciphertext.class);
        mockCiphertext2 = mock(Ciphertext.class);

        mockStatement = mock(SchnorrStatement.class); // Mock specific statement if needed
        mockProof = mock(SchnorrProof.class); // Mock specific proof type
    }

    // --- Constructor Tests ---
    @Test
    void constructor_nullElGamalCipher_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(null, keyService, schnorrProver, schnorrVerifier);
        });
    }

    @Test
    void constructor_nullKeyService_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(elGamalCipher, null, schnorrProver, schnorrVerifier);
        });
    }

    @Test
    void constructor_nullProver_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(elGamalCipher, keyService, null, schnorrVerifier);
        });
    }

    @Test
    void constructor_nullVerifier_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(elGamalCipher, keyService, schnorrProver, null);
        });
    }


    // --- castVote Tests ---
    @Test
    void testCastVote_Success() throws VotingException { // Add throws clause
        // Arrange
        // Encode vote string to BigInteger as done in VoteServiceImpl
        byte[] voteBytes = sampleVote.getSelectedOption().getBytes(StandardCharsets.UTF_8);
        BigInteger voteAsInt = new BigInteger(1, voteBytes); // Ensure positive

        Ciphertext expectedCiphertext = new Ciphertext(BigInteger.valueOf(123), BigInteger.valueOf(456)); // Correct constructor

        // Correct encrypt signature: publicKey, message
        when(elGamalCipher.encrypt(eq(samplePublicKey), eq(voteAsInt)))
                .thenReturn(expectedCiphertext);

        // Act
        // Correct castVote signature: credentials, vote, publicKey
        EncryptedVote encryptedVote = voteService.castVote(sampleCredentials, sampleVote, samplePublicKey);

        // Assert
        assertNotNull(encryptedVote);
        assertEquals(expectedCiphertext, encryptedVote.getVoteCiphertext()); // Correct getter
        assertTrue(encryptedVote.getValidityProof().isEmpty(), "Proof should be Optional.empty for basic castVote");

        // Verify interaction (correct signature)
        verify(elGamalCipher, times(1)).encrypt(eq(samplePublicKey), eq(voteAsInt));
    }

    @Test
    void testCastVote_NullCredentials() {
        assertThrows(NullPointerException.class, () -> {
            voteService.castVote(null, sampleVote, samplePublicKey);
        });
    }

    @Test
    void testCastVote_NullVote() {
        assertThrows(NullPointerException.class, () -> {
            voteService.castVote(sampleCredentials, null, samplePublicKey);
        });
    }

     @Test
    void testCastVote_NullVoteOption() {
        // Instantiate Vote with null option locally for this test
        Vote voteWithNullOption = new Vote(null);
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            voteService.castVote(sampleCredentials, voteWithNullOption, samplePublicKey);
        });
        assertEquals("Vote option cannot be null or empty", thrown.getMessage());
    }

    @Test
    void testCastVote_EmptyVoteOption() {
         IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            voteService.castVote(sampleCredentials, voteWithEmptyOption, samplePublicKey);
        });
        assertEquals("Vote option cannot be null or empty", thrown.getMessage());
    }

    @Test
    void testCastVote_MessageTooLarge() {
        // Create a vote option whose byte representation is >= p
        // This is hard to guarantee precisely, but we can use a very long string
        String longOption = "A".repeat(200); // Likely > 128 bits when UTF-8 encoded
        Vote largeVote = new Vote(longOption);
        byte[] voteBytes = longOption.getBytes(StandardCharsets.UTF_8);
        BigInteger voteAsInt = new BigInteger(1, voteBytes);

        // Assume this voteAsInt is >= p for the test setup
        assertTrue(voteAsInt.compareTo(p) >= 0, "Test setup requires encoded vote >= p");

        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.castVote(sampleCredentials, largeVote, samplePublicKey);
        });
        // The original VotingException is caught and wrapped
        assertEquals("Error casting vote: Vote encoding results in a value too large for the ElGamal parameters.", thrown.getMessage());
    }


    @Test
    void testCastVote_EncryptionError() {
        // Arrange
        byte[] voteBytes = sampleVote.getSelectedOption().getBytes(StandardCharsets.UTF_8);
        BigInteger voteAsInt = new BigInteger(1, voteBytes);
        RuntimeException encryptionException = new RuntimeException("Encryption failed"); // Or a more specific crypto exception if defined

        when(elGamalCipher.encrypt(eq(samplePublicKey), eq(voteAsInt)))
                .thenThrow(encryptionException);

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.castVote(sampleCredentials, sampleVote, samplePublicKey);
        }, "Should throw VotingException when encryption fails");

        assertEquals("Error casting vote: Encryption failed", thrown.getMessage()); // Corrected message
        assertEquals(encryptionException, thrown.getCause());
        verify(elGamalCipher, times(1)).encrypt(eq(samplePublicKey), eq(voteAsInt));
    }

    @Test
    void testCastVote_NullPublicKey() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            voteService.castVote(sampleCredentials, sampleVote, null);
        }, "Should throw NullPointerException if public key is null");
    }

    // --- tallyVotes Tests ---
    @Test
    void testTallyVotes_Success() throws VotingException { // Add throws clause
        // Arrange
        // Correct EncryptedVote constructor: ciphertext, proof (can be null)
        EncryptedVote ev1 = new EncryptedVote(mockCiphertext1, null);
        EncryptedVote ev2 = new EncryptedVote(mockCiphertext2, null);
        List<EncryptedVote> encryptedVotes = Arrays.asList(ev1, ev2);

        BigInteger decryptedValue1 = BigInteger.ONE; // Represents candidate A
        BigInteger decryptedValue2 = BigInteger.TWO; // Represents candidate B (example)
        BigInteger expectedTally = decryptedValue1.add(decryptedValue2); // Simple sum for example

        // Mock decryption for each ciphertext (Correct signature: privateKey, ciphertext)
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(mockCiphertext1))).thenReturn(decryptedValue1);
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(mockCiphertext2))).thenReturn(decryptedValue2);

        // Act
        Object tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

        // Assert
        assertNotNull(tallyResult);
        assertTrue(tallyResult instanceof BigInteger, "Tally result should be a BigInteger sum");
        assertEquals(expectedTally, (BigInteger) tallyResult);

        // Verify interactions (Correct signature)
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(mockCiphertext1));
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(mockCiphertext2));
        verify(elGamalCipher, times(encryptedVotes.size())).decrypt(eq(samplePrivateKey), any(Ciphertext.class));
    }

    @Test
    void testTallyVotes_EmptyList() throws VotingException {
        // Arrange
        List<EncryptedVote> emptyList = Collections.emptyList(); // Use Collections.emptyList()

        // Act
        Object tallyResult = voteService.tallyVotes(emptyList, samplePrivateKey);

        // Assert
        assertNotNull(tallyResult);
        assertTrue(tallyResult instanceof BigInteger, "Tally result should be a BigInteger");
        assertEquals(BigInteger.ZERO, (BigInteger) tallyResult, "Tally of empty list should be zero");
        verify(elGamalCipher, never()).decrypt(any(), any()); // Decryption should not be called
    }

     @Test
    void testTallyVotes_ListWithNullVote() throws VotingException {
        // Arrange
        EncryptedVote ev1 = new EncryptedVote(mockCiphertext1, null);
        List<EncryptedVote> encryptedVotes = Arrays.asList(ev1, null); // Add null entry
        BigInteger decryptedValue1 = BigInteger.TEN;
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(mockCiphertext1))).thenReturn(decryptedValue1);

        // Act
        Object tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

        // Assert: Should skip the null entry and tally the valid one
        assertEquals(decryptedValue1, tallyResult);
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(mockCiphertext1));
        verify(elGamalCipher, times(1)).decrypt(any(), any()); // Called only once
    }

    @Test
    void testTallyVotes_ListWithVoteHavingNullCiphertext() throws VotingException {
        // Arrange
        EncryptedVote ev1 = new EncryptedVote(mockCiphertext1, null);
        EncryptedVote evWithNullCipher = new EncryptedVote(null, null); // Vote with null ciphertext
        List<EncryptedVote> encryptedVotes = Arrays.asList(ev1, evWithNullCipher);
        BigInteger decryptedValue1 = BigInteger.TEN;
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(mockCiphertext1))).thenReturn(decryptedValue1);

        // Act
        Object tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

        // Assert: Should skip the entry with null ciphertext and tally the valid one
        assertEquals(decryptedValue1, tallyResult);
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(mockCiphertext1));
        verify(elGamalCipher, times(1)).decrypt(any(), any()); // Called only once
    }


    @Test
    void testTallyVotes_DecryptionError() {
        // Arrange
        EncryptedVote ev1 = new EncryptedVote(mockCiphertext1, null);
        List<EncryptedVote> encryptedVotes = List.of(ev1);
        RuntimeException decryptionException = new RuntimeException("Decryption failed");

        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(mockCiphertext1)))
                .thenThrow(decryptionException);

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.tallyVotes(encryptedVotes, samplePrivateKey);
        }, "Should throw VotingException when decryption fails");

        assertEquals("Error decrypting a vote during tally: Decryption failed", thrown.getMessage()); // Corrected message
        assertEquals(decryptionException, thrown.getCause());
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(mockCiphertext1));
    }

     @Test
    void testTallyVotes_NullPrivateKey() {
        // Arrange
        EncryptedVote ev1 = new EncryptedVote(mockCiphertext1, null);
        List<EncryptedVote> encryptedVotes = List.of(ev1);

        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            voteService.tallyVotes(encryptedVotes, null);
        }, "Should throw NullPointerException if private key is null");
    }

    // --- verifyVote Tests ---
    @Test
    void testVerifyVote_WithValidSchnorrProof() throws VotingException, ZkpException { // Add throws
        // Arrange
        // Correct EncryptedVote constructor
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof);
        // Ensure arguments match SchnorrVerifier.verifyProof(SchnorrStatement, SchnorrProof)
        when(schnorrVerifier.verifyProof(eq(mockStatement), eq(mockProof))).thenReturn(true);

        // Act
        boolean isValid = voteService.verifyVote(encryptedVoteWithProof, mockStatement, mockProof);

        // Assert
        assertTrue(isValid);
        verify(schnorrVerifier, times(1)).verifyProof(eq(mockStatement), eq(mockProof));
    }

    @Test
    void testVerifyVote_NullEncryptedVote() {
         assertThrows(NullPointerException.class, () -> {
            voteService.verifyVote(null, mockStatement, mockProof);
        });
    }


    @Test
    void testVerifyVote_VerifierThrowsZkpException() throws ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof);
        ZkpException zkpException = new ZkpException("Verifier error");

        when(schnorrVerifier.verifyProof(eq(mockStatement), eq(mockProof)))
                .thenThrow(zkpException);

        // Act & Assert
        // Update: The service method currently propagates ZkpException directly.
        // Test should expect ZkpException as per current implementation.
        ZkpException thrown = assertThrows(ZkpException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, mockStatement, mockProof);
        }, "Should throw ZkpException when verifier throws ZkpException");

        // Assert that the caught exception is the exact instance we expected
        assertSame(zkpException, thrown, "The caught exception should be the same instance thrown by the mock");
        assertEquals("Verifier error", thrown.getMessage()); // Verify the message is correct on the caught instance
        verify(schnorrVerifier, times(1)).verifyProof(eq(mockStatement), eq(mockProof));
    }

     @Test
    void testVerifyVote_VerifierThrowsRuntimeException() throws ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof);
        RuntimeException runtimeException = new RuntimeException("Unexpected verifier error");

        when(schnorrVerifier.verifyProof(eq(mockStatement), eq(mockProof)))
                .thenThrow(runtimeException);

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, mockStatement, mockProof);
        }, "Should wrap unexpected exceptions in VotingException");

        assertEquals("Unexpected error during vote verification: Unexpected verifier error", thrown.getMessage());
        assertSame(runtimeException, thrown.getCause());
        verify(schnorrVerifier, times(1)).verifyProof(eq(mockStatement), eq(mockProof));
    }


    @Test
    void testVerifyVote_WithInvalidSchnorrProof() throws VotingException, ZkpException { // Add throws
        // Arrange
        // Correct EncryptedVote constructor
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext2, mockProof);
        when(schnorrVerifier.verifyProof(eq(mockStatement), eq(mockProof))).thenReturn(false);

        // Act
        boolean isValid = voteService.verifyVote(encryptedVoteWithProof, mockStatement, mockProof);

        // Assert
        assertFalse(isValid);
        verify(schnorrVerifier, times(1)).verifyProof(eq(mockStatement), eq(mockProof));
    }

    @Test
    void testVerifyVote_NullProofParameter() throws VotingException, ZkpException { // Add throws
        // Arrange
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof); // EV has a proof internally
        // Act
        // Pass null explicitly for the proof parameter to test that specific path in verifyVote
        boolean isValid = voteService.verifyVote(encryptedVoteWithProof, mockStatement, null);

        // Assert
        assertFalse(isValid, "Verification should fail if the provided proof parameter is null");
        verify(schnorrVerifier, never()).verifyProof(any(), any()); // Verifier should not be called
    }

    @Test
    void testVerifyVote_StatementNotSchnorr() throws VotingException, ZkpException {
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof);
        Statement wrongStatement = mock(Statement.class); // Mock the interface, not SchnorrStatement

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            voteService.verifyVote(encryptedVoteWithProof, wrongStatement, mockProof);
        });
        assertEquals("Statement must be an instance of SchnorrStatement for verification.", thrown.getMessage());
        verify(schnorrVerifier, never()).verifyProof(any(), any());
    }

    @Test
    void testVerifyVote_ProofNotSchnorr() throws VotingException, ZkpException {
        EncryptedVote encryptedVoteWithProof = new EncryptedVote(mockCiphertext1, mockProof);
        Proof wrongProof = mock(Proof.class); // Mock the interface, not SchnorrProof

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            voteService.verifyVote(encryptedVoteWithProof, mockStatement, wrongProof);
        });
        assertEquals("Proof must be an instance of SchnorrProof for verification.", thrown.getMessage());
        verify(schnorrVerifier, never()).verifyProof(any(), any());
    }

}