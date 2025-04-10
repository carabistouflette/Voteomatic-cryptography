# Vote-o-matic Cryptography Project TODO

This document lists identified issues, potential improvements, and security vulnerabilities found during the analysis of the project.

## I. Security Vulnerabilities (High Priority)

1.  **Insecure Key Serialization (Major)**
    *   **Description:** ~~`KeyServiceImpl` uses standard Java serialization (`ObjectOutputStream`/`ObjectInputStream`) for keys, which is vulnerable to deserialization attacks.~~ **[OBSOLETE]** The code currently uses custom `DataOutputStream`/`DataInputStream` based serialization (see `KeyServiceImpl` lines 211-281), which avoids the primary Java deserialization vulnerability. ~~`PublicKey` and `PrivateKey` implement `Serializable`.~~ **[INCORRECT]** These classes do not implement `Serializable`.
    *   **Location:**
        *   `src/main/java/com/voteomatic/cryptography/keymanagement/KeyServiceImpl.java` (Serialization logic: lines 211-281; Usage: lines 106-107, 127-128, 157)
        *   `src/main/java/com/voteomatic/cryptography/core/elgamal/PublicKey.java`
        *   `src/main/java/com/voteomatic/cryptography/core/elgamal/PrivateKey.java`
    *   **Suggestion:** ~~Replace Java serialization with a secure format (e.g., ASN.1 DER, PEM). Remove `implements Serializable`.~~ **[DONE/NA]** Consider evaluating if the current custom serialization is sufficient or if migrating to a standard format like PEM/DER (using libraries like BouncyCastle) is desired for interoperability/robustness, although the original reported vulnerability is not present.

2.  **Insecure Schnorr Challenge Hashing**
    *   **Description:** Challenge `c` is computed by hashing string representations, not canonical byte representations. This is insecure.
    *   **Location:**
        *   `src/main/java/com/voteomatic/cryptography/core/zkp/SchnorrProver.java` (lines 102-107)
        *   `src/main/java/com/voteomatic/cryptography/core/zkp/SchnorrVerifier.java` (lines 97-102)
    *   **Suggestion:** Implement robust serialization using canonical byte representations for all hashed data.

3.  **Potential Timing Side-Channels**
    *   **Description:** `BigInteger` operations (`modPow`, `modInverse`) are not guaranteed constant-time, potentially leaking secrets.
    *   **Location:**
        *   `src/main/java/com/voteomatic/cryptography/core/elgamal/ElGamalCipherImpl.java` (lines 76, 79, 114, 119)
        *   `src/main/java/com/voteomatic/cryptography/core/zkp/SchnorrProver.java` (line 74)
        *   `src/main/java/com/voteomatic/cryptography/core/zkp/SchnorrVerifier.java` (lines 73, 76)
        *   `src/main/java/com/voteomatic/cryptography/keymanagement/KeyServiceImpl.java` (line 73)
    *   **Suggestion:** Use constant-time implementations (e.g., via BouncyCastle).

## II. Correctness and Implementation Issues

4.  **Flawed Vote Encoding and Tallying**
    *   **Description:** Direct `BigInteger` encoding of vote strings and summation is semantically incorrect for tallying and incompatible with homomorphic addition.
    *   **Location:** `src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java` (Encoding: lines 55-69; Tallying: lines 105-106)
    *   **Suggestion:** Implement proper vote encoding (e.g., encrypt 1 for chosen option) and update tallying logic.

5.  **Zero-Knowledge Proofs Not Implemented in Voting**
    *   **Description:** ZKP mechanism is not integrated into `VoteServiceImpl`. `castVote` generates null proof, `verifyVote` doesn't verify.
    *   **Location:** `src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java` (lines 74-75, 120-130)
    *   **Suggestion:** Implement ZKP generation in `castVote` and verification in `verifyVote`.

6.  **Lack of Cryptographic Parameter Validation**
    *   **Description:** Constructors lack validation for cryptographic properties (primality, generator order, range checks).
    *   **Location:** `PublicKey.java` (lines 24-32), `PrivateKey.java` (lines 25-33), likely others.
    *   **Suggestion:** Add cryptographic validation checks.

7.  **Suboptimal Key Generation Ranges**
    *   **Description:** Keys `x` and `k` generated relative to `p` instead of subgroup order `q`.
    *   **Location:** `KeyServiceImpl.java` (lines 55-59), `ElGamalCipherImpl.java` (lines 54-69)
    *   **Suggestion:** Generate keys in `[1, q-1]` if `q` is known, otherwise document rationale.

8.  **Ambiguous `tallyVotes` Return Type**
    *   **Description:** `VoteService.tallyVotes` returns `Object`, implementation returns `BigInteger`.
    *   **Location:** `VoteService.java` (Interface), `VoteServiceImpl.java` (lines 88, 116)
    *   **Suggestion:** Change return type to be specific (e.g., `Map<String, Integer>`, custom class).

## III. Testing and Dependencies

9.  **Insufficient Test Coverage**
    *   **Description:** Tests lack coverage for edge cases, errors, nulls, invalid parameters.
    *   **Location:** All `src/test/java/...` files.
    *   **Suggestion:** Add comprehensive test cases for failure scenarios.

10. **Use of Toy Cryptographic Parameters in Tests**
    *   **Description:** Tests use small, insecure parameters (e.g., p=23).
    *   **Location:** `ElGamalCipherImplTest.java` (lines 37-38), `SchnorrProtocolTest.java` (lines 37-39).
    *   **Suggestion:** Add tests with realistic parameters.

11. **Tests Masking Implementation Flaws**
    *   **Description:** Some tests pass despite underlying flaws due to mirroring implementation or using mocks inappropriately.
    *   **Location:** `SchnorrProtocolTest.java`, `VoteServiceImplTest.java`.
    *   **Suggestion:** Rewrite tests after fixing flaws; use integration tests.

12. **Outdated Dependencies**
    *   **Description:** Older JUnit 5 and Maven Surefire plugin versions.
    *   **Location:** `pom.xml` (lines 19, 27, 33, 86)
    *   **Suggestion:** Update dependencies to latest stable releases.

## IV. Minor Issues / Code Smells

13. **Unused Dependency (`keyService` in `VoteServiceImpl`)**
    *   **Description:** `keyService` injected but not used.
    *   **Location:** `src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java` (lines 21, 35)
    *   **Suggestion:** Remove or comment if for future use.

14. **Basic Error Handling in Tallying**
    *   **Description:** Uses `System.err` and basic exceptions.
    *   **Location:** `src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java` (lines 95-100, 107-112)
    *   **Suggestion:** Implement defined error policy and use a logging framework.

15. **Potential Information Leakage with Zero Message (ElGamal)**
    *   **Description:** Encrypting `message = 0` might leak information.
    *   **Location:** `src/main/java/com/voteomatic/cryptography/core/elgamal/ElGamalCipherImpl.java` (lines 48-51)
    *   **Suggestion:** Disallow encrypting zero or document risks.