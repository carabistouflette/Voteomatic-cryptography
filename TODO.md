# Voteomatic Cryptography - TODO List

This document lists identified issues and potential improvements for the Voteomatic Cryptography project based on code analysis.

## Critical Issues

### Voting Logic (`voting/VoteServiceImpl.java`)

*   **Issue:** Incorrect Tallying Method. Decrypts each vote individually before summing, completely violating ballot secrecy.
    *   **Solution:** Implement correct homomorphic tallying: Multiply the ElGamal ciphertexts component-wise (`C = C1 * C2 * ... * Cn`) and decrypt *only* the final combined ciphertext `C`.
*   **Issue:** Unsuitable Vote Encoding. Encodes vote strings directly to `BigInteger` via UTF-8 bytes. This is incompatible with meaningful homomorphic tallying.
    *   **Solution:** Implement a proper encoding scheme mapping vote choices to group elements suitable for homomorphic addition (e.g., "Yes" -> `g^1`, "No" -> `g^0`).
*   **Issue:** Missing ZKP Generation in `castVote`. No proof of vote validity (e.g., proving the encrypted value corresponds to a valid option) is generated.
    *   **Solution:** Integrate ZKP generation (e.g., Schnorr proof of knowledge of the discrete log of the plaintext, or a proof of valid range/set membership) into the `castVote` method. The proof should accompany the ciphertext.

## Security Vulnerabilities & Best Practices

### Core ElGamal (`core/elgamal/ElGamalCipherImpl.java`)

*   **Issue:** Textbook ElGamal Malleability. Vulnerable to ciphertext manipulation.
    *   **Solution:** Consider using a non-malleable variant (e.g., Cramer-Shoup) or integrate NIZKs to prove plaintext properties.
*   **Issue:** Lack of Cryptographic Parameter Validation. Assumes `p` and `g` are valid.
    *   **Solution:** Implement robust validation of `p` and `g` during key generation/loading (primality, safe prime, generator order).
*   **Issue:** Inadequate Message Encoding. Treats messages directly as `BigInteger`.
    *   **Solution:** Define and implement a clear, secure encoding scheme mapping application data (votes) to group elements.
*   **Issue:** Suboptimal Ephemeral Key (`k`) Range. Uses `[1, p-2]`.
    *   **Solution:** Use the subgroup order `q` and generate `k` in `[1, q-1]`.
*   **Issue:** Potential Timing Side-Channels. `BigInteger` operations may not be constant-time.
    *   **Solution:** Consider using cryptographic libraries with constant-time implementations.

### Schnorr ZKP (`core/zkp/SchnorrProver.java`, `core/zkp/SchnorrVerifier.java`)

*   **Issue:** Non-Standard Challenge Hash Input Serialization. Custom `writeBigIntegerWithLength`.
    *   **Solution:** Use a well-defined, standard, canonical serialization format for hashing inputs.
*   **Issue:** Lack of Cryptographic Parameter Validation. Assumes group parameters (`p`, `q`, `g`) are valid.
    *   **Solution:** Validate parameters during setup or loading.
*   **Issue:** Potential Timing Side-Channels. `BigInteger` operations.
    *   **Solution:** Use constant-time implementations where feasible.

### Key Management (`keymanagement/KeyServiceImpl.java`)

*   **Issue:** Lack of Cryptographic Parameter Validation. Constructor accepts `p` and `g` without validation.
    *   **Solution:** Add validation for `p` (primality, safe prime) and `g` (generator order).
*   **Issue:** Suboptimal Private Key (`x`) Range. Generates `x` in `[1, p-1]`.
    *   **Solution:** Generate `x` within the subgroup order `[1, q-1]`.
*   **Issue:** Custom Key Serialization Format. Non-standard binary format.
    *   **Solution:** Use standard, interoperable formats (JCA `KeySpec`, PEM, JWK, Protobuf).
*   **Issue:** Incomplete Public Key Integrity Check (`verifyKeyIntegrity`). Lacks subgroup membership check for `y`.
    *   **Solution:** Implement the subgroup membership check (`y^q mod p == 1`).

## Structural & Code Quality Issues

### Schnorr ZKP (`core/zkp/SchnorrProver.java`, `core/zkp/SchnorrVerifier.java`)

*   **Issue:** Code Duplication in Challenge Generation. `computeChallenge` logic duplicated.
    *   **Solution:** Refactor into a shared utility class/method.

### Voting Logic (`voting/VoteServiceImpl.java`)

*   **Issue:** Structural - Tight Coupling in `verifyVote`. Uses `instanceof` for ZKP types.
    *   **Solution:** Use a more flexible approach (generics, factories) if multiple ZKP schemes are needed.

### Key Management (`keymanagement/KeyServiceImpl.java`)

*   **Issue:** Parameter Rigidity. Ties all keys to a single `p` and `g`.
    *   **Solution:** Consider designs allowing management of keys with different parameter sets if needed.

### Security Utilities (`securityutils/`)

*   **Issue:** Tight Coupling in `DigitalSignatureImpl.java`. Uses `instanceof` for key types.
    *   **Solution:** Modify key interfaces to include methods for retrieving underlying JCA objects.
*   **Issue:** Generic Exception Handling. Catches generic `Exception`.
    *   **Solution:** Catch more specific exceptions where possible; document if generic `Exception` is unavoidable.