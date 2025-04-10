package com.voteomatic.cryptography;

import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipherImpl;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.io.InMemoryKeyStorageHandler;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.core.zkp.SchnorrProver;
import com.voteomatic.cryptography.core.zkp.SchnorrVerifier;
import com.voteomatic.cryptography.core.zkp.ZkpException; // Add missing import
import com.voteomatic.cryptography.core.zkp.ZkpProver;
import com.voteomatic.cryptography.core.zkp.ZkpVerifier;
import com.voteomatic.cryptography.keymanagement.KeyManagementException;
import com.voteomatic.cryptography.keymanagement.KeyPair;
import com.voteomatic.cryptography.keymanagement.KeyService; // Add missing import
import com.voteomatic.cryptography.keymanagement.KeyServiceImpl;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SHA256HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
import com.voteomatic.cryptography.voting.*; // Import all voting classes
import com.voteomatic.cryptography.voting.VotingException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class EndToEndTest {

    // Define ElGamal parameters (use appropriate values for production)
    // Using smaller, standard values for testing convenience. p=107 (prime), g=2 (generator)
    // Using a larger 512-bit safe prime (RFC 3526 Group 2) for testing
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = new BigInteger("2");

    private KeyService keyService;
    private VoteService voteService;
    private ElGamalCipher elGamalCipher;
    private KeyStorageHandler keyStorageHandler;
    private SecureRandomGenerator secureRandomGenerator;
    private ZkpProver prover; // Should be SchnorrProver
    private ZkpVerifier verifier; // Should be SchnorrVerifier
    private HashAlgorithm hashAlgorithm;


    @BeforeEach
    void setUp() {
        keyStorageHandler = new InMemoryKeyStorageHandler();
        secureRandomGenerator = new SecureRandomGeneratorImpl();
        hashAlgorithm = new SHA256HashAlgorithm(); // Instantiate the hash algorithm
        prover = new SchnorrProver(hashAlgorithm, secureRandomGenerator); // Pass both dependencies
        verifier = new SchnorrVerifier(hashAlgorithm); // Pass hash algorithm

        // Instantiate services with all required dependencies
        keyService = new KeyServiceImpl(P, G, keyStorageHandler, secureRandomGenerator);
        elGamalCipher = new ElGamalCipherImpl(secureRandomGenerator);
        voteService = new VoteServiceImpl(elGamalCipher, keyService, prover, verifier);
    }

    @Test
    void testFullVotingWorkflow() throws KeyManagementException, VotingException, ZkpException { // Add ZkpException
        // 1. Generate Key Pair
        KeyPair keyPair = keyService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivateKey();
        assertNotNull(publicKey, "Public key should not be null");
        assertNotNull(privateKey, "Private key should not be null");

        // 2. Prepare Vote
        String selectedOption = "candidate-42";
        Vote originalVote = new Vote(selectedOption); // Use the correct constructor/method if different

        // 3. Create Dummy Voter Credentials (using correct constructor)
        VoterCredentials credentials = new VoterCredentials("test-voter");

        // 4. Cast Vote (Encrypt) using the correct service method
        EncryptedVote encryptedVote = voteService.castVote(credentials, originalVote, publicKey);
        assertNotNull(encryptedVote, "Encrypted vote should not be null");
        assertNotNull(encryptedVote.getVoteCiphertext(), "Ciphertext within encrypted vote should not be null");
        // Note: ZKP Proof might be null depending on castVote implementation

        // 5. Decrypt Vote (Simulated Tally)
        // Use getVoteCiphertext() and correct decrypt parameter order (privateKey, ciphertext)
        BigInteger decryptedMessage = elGamalCipher.decrypt(privateKey, encryptedVote.getVoteCiphertext());

        // 6. Verify Decryption
        // Convert original vote message (selected option) to BigInteger for comparison
        // Use getSelectedOption()
        BigInteger originalMessageBigInt = new BigInteger(1, originalVote.getSelectedOption().getBytes(StandardCharsets.UTF_8));

        assertEquals(originalMessageBigInt, decryptedMessage, "Decrypted message should match the original vote's message");

        // Optional: Convert back to String to double-check
        String decryptedCandidateId;
        byte[] decryptedBytes = decryptedMessage.toByteArray();
        // Handle potential leading zero byte added by BigInteger.toByteArray()
        if (decryptedBytes.length > 1 && decryptedBytes[0] == 0) {
             byte[] correctedBytes = new byte[decryptedBytes.length - 1];
            System.arraycopy(decryptedBytes, 1, correctedBytes, 0, correctedBytes.length);
            decryptedCandidateId = new String(correctedBytes, StandardCharsets.UTF_8);
       } else {
            decryptedCandidateId = new String(decryptedBytes, StandardCharsets.UTF_8);
       }

        assertEquals(selectedOption, decryptedCandidateId, "Decrypted candidate ID string should match original");
    }
}