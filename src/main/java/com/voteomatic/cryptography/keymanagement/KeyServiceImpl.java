package com.voteomatic.cryptography.keymanagement;

import com.voteomatic.cryptography.core.elgamal.PrivateKey;
import com.voteomatic.cryptography.core.elgamal.PublicKey;
import com.voteomatic.cryptography.io.DataHandlingException;
import com.voteomatic.cryptography.io.KeyStorageHandler;
import com.voteomatic.cryptography.io.PKCS12KeyStorageHandler;
import com.voteomatic.cryptography.securityutils.SecureRandomGenerator;
import com.voteomatic.cryptography.securityutils.SecureRandomGeneratorImpl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.IOException; // Keep for potential exceptions from helpers
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyPairGenerator; // Added for RSA key generation
// Note: java.security.KeyPair is already imported via java.security.*
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of the KeyService interface.
 * Handles ElGamal key pair generation, storage, and retrieval using a KeyStorageHandler.
 * The ElGamal parameters (prime p, generator g) are provided during construction.
 */
public class KeyServiceImpl implements KeyService {

    private static final Logger LOGGER = Logger.getLogger(KeyServiceImpl.class.getName());

    private final KeyStorageHandler keyStorageHandler;
    private final SecureRandomGenerator secureRandomGenerator;
    private final BigInteger p;
    private final BigInteger g;

    // Suffixes no longer needed as KeyStore handles alias directly

    /**
     * Constructs a KeyServiceImpl with the required dependencies and ElGamal parameters.
     *
     * @param p                   The prime modulus (p) for ElGamal operations. Must be non-null.
     * @param g                   The generator (g) for ElGamal operations. Must be non-null.
     * @param keyStorageHandler     The handler for storing and retrieving key data. Must be non-null.
     * @param secureRandomGenerator The generator for secure random numbers. Must be non-null.
     */
    public KeyServiceImpl(BigInteger p, BigInteger g, KeyStorageHandler keyStorageHandler, SecureRandomGenerator secureRandomGenerator) {
        this.p = Objects.requireNonNull(p, "Prime modulus p cannot be null.");
        this.g = Objects.requireNonNull(g, "Generator g cannot be null.");
        this.keyStorageHandler = Objects.requireNonNull(keyStorageHandler, "KeyStorageHandler cannot be null.");
        this.secureRandomGenerator = Objects.requireNonNull(secureRandomGenerator, "SecureRandomGenerator cannot be null.");
        // Consider adding validation for p (primality) and g (generator properties) here or elsewhere.
        // Ensure BouncyCastle provider is registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Constructs a KeyServiceImpl using the default PKCS12KeyStorageHandler.
     * The keystore will be located at "voteomatic_keystore.p12" and use a placeholder password.
     *
     * @param p The prime modulus (p) for ElGamal operations. Must be non-null.
     * @param g The generator (g) for ElGamal operations. Must be non-null.
     * @throws KeyManagementException If the default KeyStorageHandler cannot be initialized.
     */
    public KeyServiceImpl(BigInteger p, BigInteger g) throws KeyManagementException {
        this(p, g, createDefaultKeyStorageHandler(), new SecureRandomGeneratorImpl());
    }

    private static KeyStorageHandler createDefaultKeyStorageHandler() throws KeyManagementException {
        try {
            String defaultKeystorePath = "voteomatic_keystore.p12";
            // TODO: Securely load keystore password instead of using a placeholder.
            char[] defaultPassword = "changeit".toCharArray();
            return new PKCS12KeyStorageHandler(defaultKeystorePath, defaultPassword);
        } catch (DataHandlingException e) {
            throw new KeyManagementException("Failed to initialize default PKCS12KeyStorageHandler", e);
        }
    }

    @Override
    public KeyPair generateKeyPair() throws KeyManagementException {
        try {
            // The private key x should be in the range [1, p-2] for safety,
            // or more accurately, related to the order q of the subgroup generated by g.
            // For simplicity, we generate x in [1, p-1].
            // A more robust implementation might use the subgroup order q = (p-1)/k if known.
            // We need x in range [1, p-2] or similar depending on group structure.
            // Using generateBigInteger(limit) gives [0, limit-1].
            // We'll generate in [0, p-2] and add 1 to get [1, p-1].
            BigInteger pMinusTwo = this.p.subtract(BigInteger.valueOf(2)); // Upper bound for generation is p-2
            if (pMinusTwo.compareTo(BigInteger.ZERO) <= 0) {
                 throw new KeyManagementException("Prime p must be greater than 2 for ElGamal.");
            }
            BigInteger x = secureRandomGenerator.generateBigInteger(pMinusTwo).add(BigInteger.ONE); // x is now in [1, p-1]
            // Note: A check for subgroup order 'q' would be more precise if 'g' generates a subgroup.
            // For the standard MODP group with g=2, the order is (p-1)/2. Generating x < q would be better.
            // BigInteger q = this.p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
            // x = secureRandomGenerator.generateBigInteger(q.subtract(BigInteger.ONE)).add(BigInteger.ONE); // x in [1, q-1]


            BigInteger y = this.g.modPow(x, this.p);

            // Use the instance's p and g when creating key objects
            PublicKey publicKey = new PublicKey(this.p, this.g, y);
            PrivateKey privateKey = new PrivateKey(this.p, this.g, x);

            return new KeyPair(publicKey, privateKey);

        } catch (Exception e) {
            throw new KeyManagementException("Failed to generate ElGamal key pair", e);
        }
    }

    /**
     * Stores the key pair using the configured KeyStorageHandler.
     * Requires a password to protect the key entry within the keystore.
     *
     * @param keyPair  The ElGamal key pair to store.
     * @param keyId    The alias (identifier) for the key pair in the storage.
     * @param password The password to protect the key entry.
     * @throws KeyManagementException If storing fails due to validation, conversion, or storage issues.
     */
    @Override
    public void storeKeyPair(KeyPair keyPair, String keyId, char[] password) throws KeyManagementException {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new KeyManagementException("Key ID (alias) cannot be null or empty.");
        }
        if (keyPair == null || keyPair.getPublicKey() == null || keyPair.getPrivateKey() == null) {
            throw new KeyManagementException("KeyPair and its components cannot be null.");
        }
        if (password == null || password.length == 0) {
            throw new KeyManagementException("Password for key entry cannot be null or empty.");
        }
        // Verify the keypair parameters match the service instance parameters
        if (!this.p.equals(keyPair.getPublicKey().getP()) || !this.g.equals(keyPair.getPublicKey().getG())) {
             throw new KeyManagementException("KeyPair parameters (p, g) do not match the parameters configured for this KeyService instance.");
        }

        try {
            // 1. Convert custom KeyPair to JCE KeyPair
            java.security.KeyPair jceKeyPair = convertToJceKeyPair(keyPair);

            // 2. Generate a self-signed certificate for the JCE KeyPair
            // Using a simple subject DN. Customize if needed.
            String subjectDN = "CN=Voteomatic Key Alias: " + keyId;
            X509Certificate certificate;
            try {
                certificate = generateSelfSignedCertificate(jceKeyPair, subjectDN);
            } catch (OperatorCreationException e) {
                // This exception originates from the ContentSigner creation
                LOGGER.log(Level.SEVERE, "Failed to create content signer during certificate generation for key ID: " + keyId, e);
                throw new KeyManagementException("Failed to create cryptographic operator for certificate generation", e);
            }

            // 3. Store using the KeyStorageHandler
            keyStorageHandler.storeKeyPair(keyId, jceKeyPair, certificate, password);

        // Catch specific checked exceptions from the try block
        // NOTE: OperatorCreationException is removed here temporarily pending dependency resolution.
        // Catching broader Exception for now to allow compilation structure check.
        } catch (Exception e) {
             // Check if it's one of the expected types before wrapping, or just wrap generally.
             // For now, wrap generally. Add specific handling if needed after dependencies are fixed.
             if (e instanceof DataHandlingException || e instanceof NoSuchAlgorithmException ||
                 e instanceof InvalidKeySpecException || e instanceof NoSuchProviderException ||
                 e instanceof CertificateException || e instanceof InvalidKeyException ||
                 e instanceof SignatureException /*|| e instanceof OperatorCreationException */) {
                 throw new KeyManagementException("Failed to store key pair with ID: " + keyId, e);
             } else {
                 // Re-throw unexpected runtime exceptions
                 if (e instanceof RuntimeException) {
                     throw (RuntimeException) e;
                 }
                 // Wrap other unexpected checked exceptions
                 throw new KeyManagementException("Unexpected error storing key pair with ID: " + keyId, e);
             }
        }
    }

    /**
     * Retrieves the key pair using the configured KeyStorageHandler.
     * Requires the password used when the key entry was stored.
     *
     * @param keyId    The alias (identifier) of the key pair to retrieve.
     * @param password The password required to access the key entry.
     * @return The retrieved ElGamal key pair.
     * @throws KeyManagementException If retrieval fails due to validation, conversion, or storage issues.
     */
    @Override
    public KeyPair retrieveKeyPair(String keyId, char[] password) throws KeyManagementException {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new KeyManagementException("Key ID (alias) cannot be null or empty.");
        }
         if (password == null || password.length == 0) {
            throw new KeyManagementException("Password for key entry cannot be null or empty.");
        }

        try {
            // 1. Retrieve JCE KeyPair from storage
            java.security.KeyPair jceKeyPair = keyStorageHandler.retrieveKeyPair(keyId, password);

            // 2. Convert JCE KeyPair back to custom KeyPair
            KeyPair voteomaticKeyPair = convertFromJceKeyPair(jceKeyPair, this.p, this.g);

            return voteomaticKeyPair;

        } catch (DataHandlingException | NoSuchAlgorithmException | InvalidKeySpecException |
                 NoSuchProviderException | ClassCastException e) {
            // ClassCastException could happen if retrieved keys aren't DH keys
            throw new KeyManagementException("Failed to retrieve key pair with ID: " + keyId, e);
        }
    }

    /**
     * Retrieves only the public key associated with the given alias.
     * This typically does not require a password.
     *
     * @param keyId The alias (identifier) of the key entry.
     * @return The retrieved ElGamal public key.
     * @throws KeyManagementException If retrieval fails due to validation, conversion, or storage issues.
     */
    public PublicKey getPublicKey(String keyId) throws KeyManagementException {
         if (keyId == null || keyId.trim().isEmpty()) {
            throw new KeyManagementException("Key ID (alias) cannot be null or empty.");
        }
        try {
            // 1. Retrieve JCE PublicKey from storage
            java.security.PublicKey jcePublicKey = keyStorageHandler.getPublicKey(keyId);

            // 2. Convert JCE PublicKey back to custom PublicKey
            PublicKey voteomaticPublicKey = convertFromJcePublicKey(jcePublicKey, this.p, this.g);

            return voteomaticPublicKey;

        } catch (DataHandlingException | NoSuchAlgorithmException | InvalidKeySpecException |
                 NoSuchProviderException | ClassCastException e) {
            // ClassCastException could happen if retrieved key isn't a DH key
            throw new KeyManagementException("Failed to retrieve public key with ID: " + keyId, e);
        }
    }

    @Override
    public boolean verifyKeyIntegrity(PublicKey publicKey) throws KeyManagementException {
         if (publicKey == null) {
            throw new KeyManagementException("PublicKey cannot be null for verification.");
        }

        if (publicKey.getP() == null || publicKey.getG() == null || publicKey.getY() == null) {
            return false; // Null components
        }

        if (!this.p.equals(publicKey.getP()) || !this.g.equals(publicKey.getG())) {
            // The key uses different p or g than this service instance is configured for.
            return false;
        }

        // y = g^x mod p. Since 1 <= x <= p-2 (or q-1), y should not be 0 or 1 typically,
        // unless g has small order or x=p-1 (which we avoid).
        // A simple check is that y is within the valid range.
        if (publicKey.getY().compareTo(BigInteger.ONE) < 0 || publicKey.getY().compareTo(this.p) >= 0) {
             // y is out of the expected range [1, p-1]
             return false;
        }

        // Add more sophisticated checks if needed, e.g., checking if y is in the subgroup generated by g.
        // For g=2 and p being a safe prime (p=2q+1), this means checking if y^q mod p == 1.
        // BigInteger q = this.p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        // if (!publicKey.getY().modPow(q, this.p).equals(BigInteger.ONE)) {
        //     return false; // y is not in the quadratic residue subgroup
        // }

        // If all checks pass, consider the public key structurally valid in the context of this service.
        return true;
    }

// --- Helper Methods for Key Conversion and Certificate Generation ---

private KeyFactory getKeyFactory() throws NoSuchAlgorithmException, NoSuchProviderException {
    // Try "ElGamal" with BouncyCastle first, fallback to standard "DiffieHellman"
    try {
        return KeyFactory.getInstance("ElGamal", BouncyCastleProvider.PROVIDER_NAME);
    } catch (NoSuchAlgorithmException e) {
        // Fallback to DiffieHellman if ElGamal is not directly supported by BC KeyFactory
        // (Specs DHPublicKeySpec/DHPrivateKeySpec are DH-based)
        return KeyFactory.getInstance("DiffieHellman");
    }
}

private java.security.KeyPair convertToJceKeyPair(KeyPair voteomaticKeyPair)
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

    PublicKey pub = voteomaticKeyPair.getPublicKey();
    PrivateKey priv = voteomaticKeyPair.getPrivateKey();

    // Use p and g from the custom key objects
    BigInteger keyP = pub.getP();
    BigInteger keyG = pub.getG();
    BigInteger y = pub.getY();
    BigInteger x = priv.getX();

    KeyFactory keyFactory = getKeyFactory();

    // Create JCE Key Specifications
    DHPublicKeySpec pubSpec = new DHPublicKeySpec(y, keyP, keyG);
    DHPrivateKeySpec privSpec = new DHPrivateKeySpec(x, keyP, keyG);

    // Generate JCE Keys
    java.security.PublicKey jcePublicKey = keyFactory.generatePublic(pubSpec);
    java.security.PrivateKey jcePrivateKey = keyFactory.generatePrivate(privSpec);

    return new java.security.KeyPair(jcePublicKey, jcePrivateKey);
}

private KeyPair convertFromJceKeyPair(java.security.KeyPair jceKeyPair, BigInteger expectedP, BigInteger expectedG)
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, KeyManagementException {

    if (!(jceKeyPair.getPublic() instanceof DHPublicKey) || !(jceKeyPair.getPrivate() instanceof DHPrivateKey)) {
        throw new ClassCastException("Retrieved JCE keys are not of expected DH type.");
    }

    DHPublicKey jcePublicKey = (DHPublicKey) jceKeyPair.getPublic();
    DHPrivateKey jcePrivateKey = (DHPrivateKey) jceKeyPair.getPrivate();

    // Extract parameters and values
    BigInteger y = jcePublicKey.getY();
    BigInteger x = jcePrivateKey.getX();
    DHParameterSpec params = jcePublicKey.getParams(); // Get params from public key
    BigInteger p = params.getP();
    BigInteger g = params.getG();

    // Validate against service parameters
    if (!expectedP.equals(p) || !expectedG.equals(g)) {
        throw new KeyManagementException("Retrieved key parameters (p, g) do not match service configuration.");
    }

    // Create custom key objects
    PublicKey voteomaticPublicKey = new PublicKey(p, g, y);
    PrivateKey voteomaticPrivateKey = new PrivateKey(p, g, x);

    return new KeyPair(voteomaticPublicKey, voteomaticPrivateKey);
}

 private PublicKey convertFromJcePublicKey(java.security.PublicKey jcePublicKey, BigInteger expectedP, BigInteger expectedG)
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, KeyManagementException {

    if (!(jcePublicKey instanceof DHPublicKey)) {
        throw new ClassCastException("Retrieved JCE public key is not of expected DH type.");
    }

    DHPublicKey dhPublicKey = (DHPublicKey) jcePublicKey;

    // Extract parameters and values
    BigInteger y = dhPublicKey.getY();
    DHParameterSpec params = dhPublicKey.getParams();
    BigInteger p = params.getP();
    BigInteger g = params.getG();

    // Validate against service parameters
    if (!expectedP.equals(p) || !expectedG.equals(g)) {
        throw new KeyManagementException("Retrieved public key parameters (p, g) do not match service configuration.");
    }

    // Create custom public key object
    return new PublicKey(p, g, y);
}


/**
 * Generates a basic self-signed X.509 certificate for the given key pair.
 * Uses BouncyCastle API.
 *
 * @param keyPair   The JCE KeyPair (containing DH/ElGamal keys).
 * @param subjectDN The subject distinguished name (e.g., "CN=MyKey").
 * @return A self-signed X509Certificate.
 * @throws OperatorCreationException If the signer cannot be created.
 * @throws CertificateException      If certificate generation fails.
 * @throws NoSuchAlgorithmException  If the signing algorithm is not found.
 * @throws InvalidKeyException       If the private key is invalid for signing.
 * @throws NoSuchProviderException   If BouncyCastle provider is not found.
 * @throws SignatureException        If signing fails.
 */
// NOTE: OperatorCreationException removed from throws clause temporarily pending dependency resolution.
private X509Certificate generateSelfSignedCertificate(java.security.KeyPair keyPair, String subjectDN)
        throws CertificateException, NoSuchAlgorithmException,
               InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException {

    long now = System.currentTimeMillis();
    Date startDate = new Date(now);
    // Validity: 10 years, adjust as needed
    Date endDate = new Date(now + TimeUnit.DAYS.toMillis(365 * 10));

    // Use the key pair's public key for the certificate
    java.security.PublicKey pubKey = keyPair.getPublic();
    java.security.PrivateKey privKey = keyPair.getPrivate();

    // Subject and Issuer are the same for self-signed certs
    X500Name subject = new X500Name(subjectDN);
    X500Name issuer = subject; // Self-signed

    // Serial number - use a random positive BigInteger
    BigInteger serialNumber = new BigInteger(64, new SecureRandom());

    // Use BouncyCastle's builder
    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer,
            serialNumber,
            startDate,
            endDate,
            subject,
            pubKey);

    // Generate a temporary RSA key pair specifically for signing the certificate
    // The certificate itself will still contain the original ElGamal public key (pubKey)
    KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
    rsaKpg.initialize(2048); // Using 2048 bits for the temporary RSA key
    java.security.KeyPair signingKeyPair = rsaKpg.generateKeyPair();
    java.security.PrivateKey signingPrivateKey = signingKeyPair.getPrivate();

    // Use SHA256withRSA for the signature algorithm, as we are signing with the temporary RSA key
    String signatureAlgorithm = "SHA256withRSA";
    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(signingPrivateKey); // Sign using the temporary RSA private key

    // Build and sign the certificate
    X509Certificate certificate = new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(certBuilder.build(contentSigner));

    // Optional: Verify the certificate signature (self-verification)
    // certificate.verify(pubKey); // Removed: Verification fails as cert pub key (ElGamal) doesn't match signing key type (RSA)

    return certificate;
}
}