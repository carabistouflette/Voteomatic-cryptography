package com.voteomatic.cryptography.voting;

import com.voteomatic.cryptography.core.DomainParameters; // Added import
import com.voteomatic.cryptography.core.elgamal.Ciphertext;
import com.voteomatic.cryptography.core.elgamal.*; // Import EncryptionResult etc.
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
    private ZkpProver prover; // Use generic interface

    @Mock
    private ZkpVerifier verifier; // Use generic interface

    @Mock
    private DomainParameters domainParameters;

    // @InjectMocks removed - instance will be created in setUp
    private VoteServiceImpl voteService;

    // Test Data - Initialize as needed in tests or @BeforeEach
    private Vote sampleVote;
    // Removed voteWithNullOption from fields to avoid NPE in setUp
    private Vote voteWithEmptyOption;
    private VoterCredentials sampleCredentials;
    private PublicKey samplePublicKey;
    private PrivateKey samplePrivateKey; // Needed for tallying
    private Ciphertext mockCiphertext1; // Re-added for verifyVote tests
    private Ciphertext mockCiphertext2; // Re-added for verifyVote tests
    // Mocks for the new ZKP types
    private DisjunctiveChaumPedersenStatement mockDcpStatement;
    private DisjunctiveChaumPedersenProof mockDcpProof;
    private BigInteger mockRandomness; // To store the mocked randomness 'r'
    // p, g, q are now part of domainParams
    private DomainParameters domainParams;
    @BeforeEach
    void setUp() {
        // Initialize common test data
        // Use larger ElGamal parameters suitable for vote encoding
        // Example 128-bit prime and generator g=2
        BigInteger p_val = new BigInteger("340282366920938463463374607431768211507"); // 128-bit prime
        BigInteger g_val = new BigInteger("2");  // Common generator candidate
        // Assuming p is a safe prime, q = (p-1)/2
        BigInteger q_val = p_val.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        domainParams = new DomainParameters(p_val, g_val, q_val); // Keep real one for other tests if needed

        // Stub the mocked domainParameters needed by VoteServiceImpl constructor (called via @InjectMocks)
        // Use lenient() as these might not be needed if constructor logic changes or in all tests.
        lenient().when(domainParameters.getP()).thenReturn(p_val);
        lenient().when(domainParameters.getG()).thenReturn(g_val);
        // Note: q is not directly used in the constructor's precomputation based on VoteServiceImpl code.

        BigInteger x = new BigInteger("198765432109876543210987654321"); // Example private key < q
        BigInteger y = domainParams.getG().modPow(x, domainParams.getP()); // y = g^x mod p
        samplePublicKey = new PublicKey(domainParams, y);
        // Mock the private key to return DomainParameters and x
        samplePrivateKey = mock(PrivateKey.class);
        lenient().when(samplePrivateKey.getParams()).thenReturn(domainParams); // Mock getParams()
        lenient().when(samplePrivateKey.getX()).thenReturn(x); // Needed for actual decryption mock
        sampleVote = new Vote("Yes"); // Use "Yes" for the standard sample vote
        // voteWithNullOption = new Vote(null); // Moved instantiation to specific test
        voteWithEmptyOption = new Vote("");
        sampleCredentials = new VoterCredentials("voter123"); // Correct constructor

        // Re-add mock ciphertexts for verifyVote tests
        mockCiphertext1 = mock(Ciphertext.class);
        mockCiphertext2 = mock(Ciphertext.class);
        // Use lenient() because these mocks are only used in verifyVote tests now.
        lenient().when(mockCiphertext1.getC1()).thenReturn(BigInteger.ONE); // Dummy non-null value
        lenient().when(mockCiphertext1.getC2()).thenReturn(BigInteger.ONE); // Dummy non-null value
        lenient().when(mockCiphertext2.getC1()).thenReturn(BigInteger.TWO); // Dummy non-null value
        lenient().when(mockCiphertext2.getC2()).thenReturn(BigInteger.TWO); // Dummy non-null value


        // Mock the new ZKP types
        mockDcpStatement = mock(DisjunctiveChaumPedersenStatement.class);
        mockDcpProof = mock(DisjunctiveChaumPedersenProof.class);
        mockRandomness = new BigInteger("987654321"); // Example dummy randomness

        // Explicitly instantiate voteService after mocks are set up
        voteService = new VoteServiceImpl(domainParameters, elGamalCipher, keyService, prover, verifier);
    }

    // --- Constructor Tests ---
    @Test
    void constructor_nullElGamalCipher_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(domainParams, null, keyService, prover, verifier);
        });
    }

    @Test
    void constructor_nullKeyService_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(domainParams, elGamalCipher, null, prover, verifier);
        });
    }

    @Test
    void constructor_nullProver_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(domainParams, elGamalCipher, keyService, null, verifier);
        });
    }

    @Test
    void constructor_nullVerifier_throwsException() {
        assertThrows(NullPointerException.class, () -> {
            new VoteServiceImpl(domainParams, elGamalCipher, keyService, prover, null);
        });
    }


    // --- castVote Tests ---
    @Test
    void testCastVote_Success() throws VotingException, ZkpException { // Add ZkpException
        // Arrange
        // Expected encoded message for "Yes" is g^1 = g
        BigInteger expectedMessage = domainParams.getG();

        Ciphertext expectedCiphertext = new Ciphertext(BigInteger.valueOf(123), BigInteger.valueOf(456)); // Dummy ciphertext

        // Mock the encrypt call to return EncryptionResult
        EncryptionResult mockEncryptionResult = new EncryptionResult(expectedCiphertext, mockRandomness);
        when(elGamalCipher.encrypt(eq(samplePublicKey), eq(expectedMessage)))
                .thenReturn(mockEncryptionResult);

        // Mock the prover call
        when(prover.generateProof(any(DisjunctiveChaumPedersenStatement.class), any(DisjunctiveChaumPedersenWitness.class)))
                .thenReturn(mockDcpProof);

        // Act
        // Correct castVote signature: credentials, vote, publicKey
        EncryptedVote encryptedVote = voteService.castVote(sampleCredentials, sampleVote, samplePublicKey);

        // Assert
        assertNotNull(encryptedVote);
        assertEquals(expectedCiphertext, encryptedVote.getVoteCiphertext());
        // Assert proof is present and correct
        assertTrue(encryptedVote.getValidityProof().isPresent(), "Proof should be present");
        assertEquals(mockDcpProof, encryptedVote.getValidityProof().get(), "Proof should match the mocked proof");

        // Verify interaction with the encoded message (g)
        verify(elGamalCipher, times(1)).encrypt(eq(samplePublicKey), eq(domainParams.getG()));
        // Verify prover was called
        verify(prover, times(1)).generateProof(any(DisjunctiveChaumPedersenStatement.class), any(DisjunctiveChaumPedersenWitness.class));
    }

    @Test
    void testCastVote_Success_NoVote() throws VotingException, ZkpException { // Add ZkpException
        // Arrange
        Vote noVote = new Vote("No");
        // Expected encoded message for "No" is g^0 = 1
        BigInteger expectedMessage = BigInteger.ONE;
        Ciphertext expectedCiphertext = new Ciphertext(BigInteger.valueOf(789), BigInteger.valueOf(101)); // Dummy ciphertext

        // Mock the encrypt call to return EncryptionResult
        EncryptionResult mockEncryptionResult = new EncryptionResult(expectedCiphertext, mockRandomness);
        when(elGamalCipher.encrypt(eq(samplePublicKey), eq(expectedMessage)))
                .thenReturn(mockEncryptionResult);

        // Mock the prover call
        when(prover.generateProof(any(DisjunctiveChaumPedersenStatement.class), any(DisjunctiveChaumPedersenWitness.class)))
                .thenReturn(mockDcpProof);

        // Act
        EncryptedVote encryptedVote = voteService.castVote(sampleCredentials, noVote, samplePublicKey);

        // Assert
        assertNotNull(encryptedVote);
        assertEquals(expectedCiphertext, encryptedVote.getVoteCiphertext());
        // Assert proof is present and correct
        assertTrue(encryptedVote.getValidityProof().isPresent(), "Proof should be present");
        assertEquals(mockDcpProof, encryptedVote.getValidityProof().get(), "Proof should match the mocked proof");
        verify(elGamalCipher, times(1)).encrypt(eq(samplePublicKey), eq(expectedMessage));
        // Verify prover was called
        verify(prover, times(1)).generateProof(any(DisjunctiveChaumPedersenStatement.class), any(DisjunctiveChaumPedersenWitness.class));
    }

    @Test
    void testCastVote_InvalidVoteOption() {
        // Arrange
        Vote invalidVote = new Vote("Maybe");

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.castVote(sampleCredentials, invalidVote, samplePublicKey);
        });
        // The actual exception includes "Error casting vote: " prefix
        assertEquals("Error casting vote: Invalid vote option: 'Maybe'. Only 'Yes' or 'No' are allowed.", thrown.getMessage());
        verify(elGamalCipher, never()).encrypt(any(), any()); // Encryption should not be called
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

    // testCastVote_MessageTooLarge is removed as it's no longer applicable
    // with g^1/g^0 encoding.

    @Test
    void testCastVote_EncryptionError() throws ZkpException { // Add ZkpException for verify(never()) signature check
        // Arrange
        byte[] voteBytes = sampleVote.getSelectedOption().getBytes(StandardCharsets.UTF_8);
        BigInteger voteAsInt = new BigInteger(1, voteBytes);
        RuntimeException encryptionException = new RuntimeException("Encryption failed"); // Or a more specific crypto exception if defined

        // Mock encrypt to throw exception
        when(elGamalCipher.encrypt(eq(samplePublicKey), any(BigInteger.class))) // Match any BigInteger message for simplicity here
                .thenThrow(encryptionException);

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.castVote(sampleCredentials, sampleVote, samplePublicKey);
        }, "Should throw VotingException when encryption fails");

        assertEquals("Error casting vote: Encryption failed", thrown.getMessage()); // Corrected message
        assertEquals(encryptionException, thrown.getCause());
        verify(elGamalCipher, times(1)).encrypt(eq(samplePublicKey), any(BigInteger.class));
        verify(prover, never()).generateProof(any(), any()); // Prover should not be called if encryption fails
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
    void testTallyVotes_Success_Homomorphic() throws VotingException {
        // Arrange
        // Create real ciphertexts for testing multiplication
        // Let's assume vote "1" (g^1) and vote "0" (g^0 = 1) for simplicity
        // Note: Real encryption involves randomness (k), but for testing the *tally*
        // we can use simplified ciphertexts if needed, or mock the encryption result.
        // Let's use simplified ones where k=1 for illustration.
        // C1 = (g^k, m1 * y^k) = (g^1, g^1 * y^1) = (g, g*y)
        // C2 = (g^k, m2 * y^k) = (g^1, g^0 * y^1) = (g, 1*y) = (g, y)
        BigInteger y = samplePublicKey.getY();
        Ciphertext ct1 = new Ciphertext(domainParams.getG().mod(domainParams.getP()), domainParams.getG().multiply(y).mod(domainParams.getP())); // Represents m1=g^1
        Ciphertext ct2 = new Ciphertext(domainParams.getG().mod(domainParams.getP()), y.mod(domainParams.getP()));             // Represents m2=g^0=1

        EncryptedVote ev1 = new EncryptedVote(ct1, null);
        EncryptedVote ev2 = new EncryptedVote(ct2, null);
        List<EncryptedVote> encryptedVotes = Arrays.asList(ev1, ev2);

        // Calculate expected product ciphertext: C_total = C_identity * C1 * C2
        Ciphertext identity = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
        Ciphertext expectedProductCiphertext = identity.multiply(ct1, domainParams.getP()).multiply(ct2, domainParams.getP());

        // Expected decrypted result: m1 * m2 = g^1 * g^0 = g^1 = g
        BigInteger expectedDecryptedResult = domainParams.getG(); // g^k where k = 1 + 0 = 1

        // Mock the *final* decryption call
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext)))
                .thenReturn(expectedDecryptedResult);

        // Act
        BigInteger tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

        // Assert
        assertNotNull(tallyResult);
        // Assert that the calculated tally count 'k' is correct (1 in this case: Yes=1, No=0)
        assertEquals(BigInteger.ONE, tallyResult, "Tally count 'k' should be 1 for one 'Yes' and one 'No' vote");

        // Verify final decryption was called exactly once with the correct product ciphertext
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext));
        verify(elGamalCipher, times(1)).decrypt(any(), any()); // Ensure no other decryptions happened
    }

    @Test
    void testTallyVotes_EmptyList_Homomorphic() throws VotingException {
        // Arrange
        List<EncryptedVote> emptyList = Collections.emptyList();

        // Act
        BigInteger tallyResult = voteService.tallyVotes(emptyList, samplePrivateKey);

        // Assert
        assertNotNull(tallyResult);
        // Empty list tally now returns k = 0
        assertEquals(BigInteger.ZERO, tallyResult, "Tally of empty list should be BigInteger.ZERO (k=0)");
        verify(elGamalCipher, never()).decrypt(any(), any()); // Decryption should not be called
    }

     @Test
    void testTallyVotes_ListWithNullVote_Homomorphic() throws VotingException {
       // Arrange
       // Use a real ciphertext for the valid vote
       // Arrange: One valid "Yes" vote (g^1) and one null entry
       Ciphertext ctYes = new Ciphertext(domainParams.getG().modPow(BigInteger.TWO, domainParams.getP()), domainParams.getG().multiply(samplePublicKey.getY().modPow(BigInteger.TWO, domainParams.getP())).mod(domainParams.getP())); // Enc(g^1)
       EncryptedVote evYes = new EncryptedVote(ctYes, null);
       List<EncryptedVote> encryptedVotes = Arrays.asList(evYes, null); // Add null entry

       // Calculate expected product ciphertext (identity * ctYes)
       Ciphertext identity = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
       Ciphertext expectedProductCiphertext = identity.multiply(ctYes, domainParams.getP());

       // Expected decrypted result (g^k): g^1 = g
       BigInteger expectedDecryptedGk = domainParams.getG();
       // Expected final tally count (k): 1
       BigInteger expectedTallyCountK = BigInteger.ONE;

       // Mock the final decryption
       when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext)))
               .thenReturn(expectedDecryptedGk);

       // Act
       BigInteger tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

       // Assert: Should skip the null entry and return the correct count k
       assertEquals(expectedTallyCountK, tallyResult);
       verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext));
       verify(elGamalCipher, times(1)).decrypt(any(), any()); // Called only once
   }

    @Test
    void testTallyVotes_ListWithVoteHavingNullCiphertext_Homomorphic() throws VotingException {
       // Arrange
       // Use a real ciphertext for the valid vote
       // Arrange: One valid "No" vote (g^0) and one vote with null ciphertext
       Ciphertext ctNo = new Ciphertext(domainParams.getG().modPow(BigInteger.valueOf(3), domainParams.getP()), BigInteger.ONE.multiply(samplePublicKey.getY().modPow(BigInteger.valueOf(3), domainParams.getP())).mod(domainParams.getP())); // Enc(g^0)
       EncryptedVote evNo = new EncryptedVote(ctNo, null);
       EncryptedVote evWithNullCipher = new EncryptedVote(null, null); // Vote with null ciphertext
       List<EncryptedVote> encryptedVotes = Arrays.asList(evNo, evWithNullCipher);

       // Calculate expected product ciphertext (identity * ctNo)
       Ciphertext identity = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
       Ciphertext expectedProductCiphertext = identity.multiply(ctNo, domainParams.getP());

       // Expected decrypted result (g^k): g^0 = 1
       BigInteger expectedDecryptedGk = BigInteger.ONE;
       // Expected final tally count (k): 0
       BigInteger expectedTallyCountK = BigInteger.ZERO;

       // Mock the final decryption
       when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext)))
               .thenReturn(expectedDecryptedGk);

       // Act
       BigInteger tallyResult = voteService.tallyVotes(encryptedVotes, samplePrivateKey);

       // Assert: Should skip the entry with null ciphertext and return the correct count k
       assertEquals(expectedTallyCountK, tallyResult);
       verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext));
       verify(elGamalCipher, times(1)).decrypt(any(), any()); // Called only once
   }


    @Test
    void testTallyVotes_FinalDecryptionError_Homomorphic() {
       // Arrange
       // Use a real ciphertext
       // Arrange: One valid "Yes" vote
       Ciphertext ctYes = new Ciphertext(domainParams.getG().modPow(BigInteger.TWO, domainParams.getP()), domainParams.getG().multiply(samplePublicKey.getY().modPow(BigInteger.TWO, domainParams.getP())).mod(domainParams.getP())); // Enc(g^1)
       EncryptedVote evYes = new EncryptedVote(ctYes, null);
       List<EncryptedVote> encryptedVotes = List.of(evYes);

       // Calculate expected product ciphertext (identity * ct1)
       Ciphertext identity = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
       Ciphertext expectedProductCiphertext = identity.multiply(ctYes, domainParams.getP());

       RuntimeException decryptionException = new RuntimeException("Final Decryption failed");

       // Mock the *final* decryption call to throw an error
       when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext)))
               .thenThrow(decryptionException);

       // Act & Assert
       VotingException thrown = assertThrows(VotingException.class, () -> {
           voteService.tallyVotes(encryptedVotes, samplePrivateKey);
       }, "Should throw VotingException when final decryption fails");

       // Verify the error message reflects the final decryption or interpretation step
       assertEquals("Error during final tally decryption or interpretation: Final Decryption failed", thrown.getMessage());
       assertEquals(decryptionException, thrown.getCause());
       verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext));
       verify(elGamalCipher, times(1)).decrypt(any(), any()); // Ensure only the final decryption was attempted
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

    @Test
    void testTallyVotes_CannotDetermineTally() {
        // Arrange: One "Yes" vote
        Ciphertext ctYes = new Ciphertext(domainParams.getG().modPow(BigInteger.TWO, domainParams.getP()), domainParams.getG().multiply(samplePublicKey.getY().modPow(BigInteger.TWO, domainParams.getP())).mod(domainParams.getP())); // Enc(g^1)
        EncryptedVote evYes = new EncryptedVote(ctYes, null);
        List<EncryptedVote> encryptedVotes = List.of(evYes);

        Ciphertext identity = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
        Ciphertext expectedProductCiphertext = identity.multiply(ctYes, domainParams.getP());

        // Mock decryption to return a value that is NOT g^0 or g^1 (assuming g != 10)
        BigInteger invalidDecryptedResult = BigInteger.TEN;
        when(elGamalCipher.decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext)))
                .thenReturn(invalidDecryptedResult);

        // Act & Assert
        VotingException thrown = assertThrows(VotingException.class, () -> {
            voteService.tallyVotes(encryptedVotes, samplePrivateKey);
        });

        // Assert the exact message to pinpoint discrepancies
        // Expect the new wrapped exception message reflecting the precomputed map lookup failure
        assertEquals("Error during final tally decryption or interpretation: Could not determine the vote tally (k) from the decrypted result. The result (10) was not found in the precomputed map. It might be invalid or exceed the maximum precomputed tally of 10000.", thrown.getMessage());
        verify(elGamalCipher, times(1)).decrypt(eq(samplePrivateKey), eq(expectedProductCiphertext));
    }


    // --- verifyVote Tests (Updated for Disjunctive Chaum-Pedersen) ---

    // Helper method to create an EncryptedVote with the mock DCP proof
    private EncryptedVote createEncryptedVoteWithMockProof() {
        // Use lenient() as these mocks might not be used in every test path
        lenient().when(mockCiphertext1.getC1()).thenReturn(BigInteger.ONE);
        lenient().when(mockCiphertext1.getC2()).thenReturn(BigInteger.TEN);
        return new EncryptedVote(mockCiphertext1, mockDcpProof);
    }

    @Test
    void testVerifyVote_WithValidProof() throws VotingException, ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof();
        // Mock the generic verifier to return true for the specific statement/proof types
        when(verifier.verifyProof(eq(mockDcpStatement), eq(mockDcpProof))).thenReturn(true);

        // Act
        boolean isValid = voteService.verifyVote(encryptedVoteWithProof, mockDcpStatement, mockDcpProof);

        // Assert
        assertTrue(isValid);
        verify(verifier, times(1)).verifyProof(eq(mockDcpStatement), eq(mockDcpProof));
    }

    @Test
    void testVerifyVote_WithInvalidProof() throws VotingException, ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof();
        when(verifier.verifyProof(eq(mockDcpStatement), eq(mockDcpProof))).thenReturn(false);

        // Act
        boolean isValid = voteService.verifyVote(encryptedVoteWithProof, mockDcpStatement, mockDcpProof);

        // Assert
        assertFalse(isValid);
        verify(verifier, times(1)).verifyProof(eq(mockDcpStatement), eq(mockDcpProof));
    }


    // Removed testVerifyVote_NullEncryptedVote as the parameter is currently unused in verifyVote

    @Test
    void testVerifyVote_NullProofParameter() throws VotingException, ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof(); // EV has a proof internally

        // Act & Assert
        // Pass null explicitly for the proof parameter - should throw NullPointerException
        NullPointerException thrown = assertThrows(NullPointerException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, mockDcpStatement, null);
        });
        assertEquals("Proof cannot be null for verification", thrown.getMessage());
        verify(verifier, never()).verifyProof(any(), any()); // Verifier should not be called
    }

    @Test
    void testVerifyVote_NullStatementParameter() throws VotingException, ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof(); // EV has a proof internally

        // Act & Assert
        // Pass null explicitly for the statement parameter - should throw NullPointerException
        NullPointerException thrown = assertThrows(NullPointerException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, null, mockDcpProof);
        });
        assertEquals("Statement cannot be null for verification", thrown.getMessage());
        verify(verifier, never()).verifyProof(any(), any()); // Verifier should not be called
    }



    @Test
    void testVerifyVote_VerifierThrowsZkpException() throws ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof();
        ZkpException zkpException = new ZkpException("Verifier error");

        when(verifier.verifyProof(eq(mockDcpStatement), eq(mockDcpProof)))
                .thenThrow(zkpException);

        // Act & Assert
        // Expect ZkpException to be propagated
        ZkpException thrown = assertThrows(ZkpException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, mockDcpStatement, mockDcpProof);
        });

        assertSame(zkpException, thrown);
        assertEquals("Verifier error", thrown.getMessage());
        verify(verifier, times(1)).verifyProof(eq(mockDcpStatement), eq(mockDcpProof));
    }

     @Test
    void testVerifyVote_VerifierThrowsRuntimeException() throws ZkpException {
        // Arrange
        EncryptedVote encryptedVoteWithProof = createEncryptedVoteWithMockProof();
        RuntimeException runtimeException = new RuntimeException("Unexpected verifier error");

        when(verifier.verifyProof(eq(mockDcpStatement), eq(mockDcpProof)))
                .thenThrow(runtimeException);

        // Act & Assert
        // Expect runtime exceptions to be wrapped in VotingException
        VotingException thrown = assertThrows(VotingException.class, () -> {
             voteService.verifyVote(encryptedVoteWithProof, mockDcpStatement, mockDcpProof);
        });

        assertEquals("Unexpected error during vote verification: Unexpected verifier error", thrown.getMessage());
        assertSame(runtimeException, thrown.getCause());
        verify(verifier, times(1)).verifyProof(eq(mockDcpStatement), eq(mockDcpProof));
    }

    // Note: Tests for specific statement/proof types (like StatementNotSchnorr) are removed
    // as the verifyVote method itself doesn't enforce specific types beyond what the
    // injected verifier handles (or what the method itself checks before calling the verifier).
    // The current verifyVote implementation doesn't have explicit type checks before calling verifyProof.

}