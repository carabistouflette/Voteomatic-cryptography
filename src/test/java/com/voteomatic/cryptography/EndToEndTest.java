package com.voteomatic.cryptography;

import static org.junit.jupiter.api.Assertions.*;

import com.voteomatic.cryptography.core.DomainParameters;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipher;
import com.voteomatic.cryptography.core.elgamal.ElGamalCipherImpl;
import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.core.zkp.ZkpException;
import com.voteomatic.cryptography.core.zkp.ZkpProver;
import com.voteomatic.cryptography.core.zkp.ZkpVerifier;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenProver;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenStatement;
import com.voteomatic.cryptography.core.zkp.chaumpedersen.DisjunctiveChaumPedersenVerifier;
import com.voteomatic.cryptography.io.DataHandlingException;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.io.PKCS12KeyStorageHandler;
import com.voteomatic.cryptography.keymanagement.KeyManagementException;
import com.voteomatic.cryptography.keymanagement.KeyPair;
import com.voteomatic.cryptography.keymanagement.KeyService;
import com.voteomatic.cryptography.keymanagement.KeyServiceImpl;
import com.voteomatic.cryptography.securityutils.HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SHA256HashAlgorithm;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;
import com.voteomatic.cryptography.voting.*;
import com.voteomatic.cryptography.voting.VotingException;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EndToEndTest {

  // Define ElGamal parameters (use appropriate values for production)
  // Using smaller, standard values for testing convenience. p=107 (prime), g=2 (generator)
  // Using a larger 512-bit safe prime (RFC 3526 Group 2) for testing
  private static final BigInteger P =
      new BigInteger(
          "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
          16);
  private static final BigInteger G_VAL = new BigInteger("2");
  // For RFC 3526 Group 2 (safe prime p = 2q + 1), q = (p-1)/2
  private static final BigInteger Q = P.subtract(BigInteger.ONE).divide(BigInteger.TWO);
  private static final DomainParameters DOMAIN_PARAMS = new DomainParameters(P, G_VAL, Q);

  private KeyService keyService;
  private VoteService voteService;
  private ElGamalCipher elGamalCipher;
  // Removed keyStorageHandler field, KeyServiceImpl manages its own handler now
  private SecureRandomGenerator secureRandomGenerator;
  private ZkpProver prover; // Will be DisjunctiveChaumPedersenProver
  private ZkpVerifier verifier; // Will be DisjunctiveChaumPedersenVerifier
  private HashAlgorithm hashAlgorithm;

  @BeforeEach
  void setUp() throws KeyManagementException, DataHandlingException { // Add throws for handlers
    KeyStorageHandler keyStorageHandler =
        PKCS12KeyStorageHandler.createWithPassword( // Use static factory method
            "test_e2e_keystore.p12",
            "testpass".toCharArray()); // Instantiate default handler for test
    secureRandomGenerator = SecureRandomGeneratorImpl.createDefault();
    hashAlgorithm = new SHA256HashAlgorithm(); // Instantiate the hash algorithm
    // Instantiate the new Disjunctive Chaum-Pedersen prover and verifier
    prover = new DisjunctiveChaumPedersenProver(secureRandomGenerator, hashAlgorithm);
    verifier = new DisjunctiveChaumPedersenVerifier(hashAlgorithm);

    // Instantiate services. KeyServiceImpl now uses its default constructor.
    keyService =
        new KeyServiceImpl(
            DOMAIN_PARAMS, keyStorageHandler, secureRandomGenerator); // Use the correct constructor
    elGamalCipher = new ElGamalCipherImpl(secureRandomGenerator);
    voteService = new VoteServiceImpl(DOMAIN_PARAMS, elGamalCipher, keyService, prover, verifier);
  }

  @Test
  void testFullVotingWorkflow()
      throws KeyManagementException, VotingException, ZkpException {
    // 1. Generate Key Pair
    KeyPair keyPair = keyService.generateKeyPair();
    PublicKey publicKey = keyPair.getPublicKey();
    PrivateKey privateKey = keyPair.getPrivateKey();
    assertNotNull(publicKey, "Public key should not be null");
    assertNotNull(privateKey, "Private key should not be null");

    // 2. Prepare Votes ("Yes" and "No")
    Vote voteYes1 = new Vote("Yes");
    Vote voteYes2 = new Vote("Yes");
    Vote voteNo1 = new Vote("No");

    // 3. Create Dummy Voter Credentials
    VoterCredentials credentials1 = new VoterCredentials("voter1");
    VoterCredentials credentials2 = new VoterCredentials("voter2");
    VoterCredentials credentials3 = new VoterCredentials("voter3");

    // 4. Cast Votes (Encrypt)
    EncryptedVote encryptedVoteYes1 = voteService.castVote(credentials1, voteYes1, publicKey);
    EncryptedVote encryptedVoteYes2 = voteService.castVote(credentials2, voteYes2, publicKey);
    EncryptedVote encryptedVoteNo1 = voteService.castVote(credentials3, voteNo1, publicKey);

    assertNotNull(encryptedVoteYes1);
    assertNotNull(encryptedVoteYes2);
    assertNotNull(encryptedVoteNo1);
    assertNotNull(encryptedVoteYes1.getVoteCiphertext());
    assertNotNull(encryptedVoteYes2.getVoteCiphertext());
    assertNotNull(encryptedVoteNo1.getVoteCiphertext());
    // Assert proofs are present
    assertTrue(
        encryptedVoteYes1.getValidityProof().isPresent(), "Proof should be present for Yes vote 1");
    assertTrue(
        encryptedVoteYes2.getValidityProof().isPresent(), "Proof should be present for Yes vote 2");
    assertTrue(
        encryptedVoteNo1.getValidityProof().isPresent(), "Proof should be present for No vote 1");

    // 4.5 Verify Proofs (Optional but recommended in E2E)
    BigInteger m0 = BigInteger.ONE; // g^0
    BigInteger m1 = publicKey.getG();

    // Verify Yes Vote 1
    DisjunctiveChaumPedersenStatement stmtYes1 =
        DisjunctiveChaumPedersenStatement.create(
            publicKey, encryptedVoteYes1.getVoteCiphertext(), m0, m1);
    assertTrue(
        voteService.verifyVote(
            encryptedVoteYes1, stmtYes1, encryptedVoteYes1.getValidityProof().get()),
        "Proof for Yes vote 1 should be valid");

    // Verify Yes Vote 2
    DisjunctiveChaumPedersenStatement stmtYes2 =
        DisjunctiveChaumPedersenStatement.create(
            publicKey, encryptedVoteYes2.getVoteCiphertext(), m0, m1);
    assertTrue(
        voteService.verifyVote(
            encryptedVoteYes2, stmtYes2, encryptedVoteYes2.getValidityProof().get()),
        "Proof for Yes vote 2 should be valid");

    // Verify No Vote 1
    DisjunctiveChaumPedersenStatement stmtNo1 =
        DisjunctiveChaumPedersenStatement.create(
            publicKey, encryptedVoteNo1.getVoteCiphertext(), m0, m1);
    assertTrue(
        voteService.verifyVote(
            encryptedVoteNo1, stmtNo1, encryptedVoteNo1.getValidityProof().get()),
        "Proof for No vote 1 should be valid");

    // 5. Tally Votes
    List<EncryptedVote> allVotes = List.of(encryptedVoteYes1, encryptedVoteYes2, encryptedVoteNo1);
    BigInteger tallyResult = voteService.tallyVotes(allVotes, privateKey);

    // 6. Verify Tally Result
    // Expected result is the count of "Yes" votes (k)
    BigInteger expectedTally = BigInteger.TWO; // Two "Yes" votes
    assertEquals(
        expectedTally, tallyResult, "Tally result should be the count of 'Yes' votes (k=2)");
  }
}
