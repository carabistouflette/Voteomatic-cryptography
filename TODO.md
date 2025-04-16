# Vote-o-matic Cryptography TODO List

This list summarizes potential improvements, issues, and tasks identified during the project analysis (April 2025).

## Security

-   [ ] **[Security][Critical]** Replace non-constant-time `BigInteger` operations (`modPow`, `modInverse`) in `ElGamalCipherImpl` and ZKP implementations (`DisjunctiveChaumPedersenProver`) with constant-time equivalents (e.g., from Bouncy Castle low-level APIs) to mitigate timing side-channel attacks.
-   [x] **[Security][High]** Implement robust serialization for Fiat-Shamir challenge generation in `DisjunctiveChaumPedersenProver` (and potentially other ZKP provers/verifiers). Avoid direct concatenation of `toByteArray()` output; use fixed-length encoding or length-prefixing.
-   [x] **[Security][High]** Replace placeholder password (`"changeit"`) in `KeyServiceImpl` with a secure loading mechanism (e.g., environment variable, configuration file, secrets manager) as intended by `PKCS12KeyStorageHandler`. (Ref: `KeyServiceImpl.java:81`)
-   [ ] **[Security][Medium]** Add robust validation for domain parameters (`p`, `q`, `g`) in the `DomainParameters` constructor or factory method (check primality, subgroup order, generator properties). (Ref: `DomainParameters.java:30`)
-   [ ] **[Security][Medium]** Enhance `PKCS12KeyStorageHandler` to support more flexible keystore password sourcing beyond just environment variables (e.g., config files, external secrets).
-   [ ] **[Security][Low]** Consider cloning the `char[] password` array passed to the `PKCS12KeyStorageHandler` constructor for enhanced security against external modification.

## Improvements & Refactoring

-   [x] **[Improvement][High]** Address the inefficient tallying mechanism in `VoteServiceImpl`. The current brute-force discrete logarithm solution will not scale. Investigate alternatives like precomputation (for small vote counts) or more advanced discrete log algorithms if larger tallies are expected.
-   [x] **[Improvement][Medium]** Add static analysis plugins (e.g., Checkstyle, PMD, SpotBugs) to `pom.xml` to enforce coding standards and automatically detect potential bugs/smells.
-   [ ] **[Refactoring][Low]** Review `KeyServiceImpl.java` (identified as >250 LOC) for potential complexity or violations of the Single Responsibility Principle. Consider breaking down functionality if appropriate.
-   [ ] **[Improvement][Low]** Update the `commons-math3` dependency in `pom.xml` to a more recent version if compatible.
-   [ ] **[Improvement][Low]** Investigate the commented-out NVD check configuration in `dependency-check-maven` plugin in `pom.xml`. Re-enable or remove if appropriate.
-   [ ] **[Refactoring][Low]** Improve exception handling consistency:
    *   Use logging framework instead of `System.err.println` in `VoteServiceImpl`.
    *   Review exception wrapping (e.g., `SecurityUtilException` in `ElGamalCipherImpl`, `IllegalArgumentException` in `VoteServiceImpl`).
-   [ ] **[Refactoring][Low]** Consider making `VoteServiceImpl` less tightly coupled to specific ZKP implementations (`DisjunctiveChaumPedersen`) if flexibility for other proof systems is desired in the future.
-   [ ] **[Improvement][Low]** Define a clear strategy for mapping application-level messages (beyond "Yes"/"No") to `BigInteger` group elements if needed for future use cases.

## Documentation

-   [ ] **[Documentation][High]** Update `DESIGN_KeyStorage.md` to accurately reflect the implemented key storage mechanism in `PKCS12KeyStorageHandler` (uses standard `KeyStore.setKeyEntry` with `java.security.KeyPair`/`Certificate`, not the proposed `SecretKeyEntry` workaround). Explain where key type conversion happens (likely in `KeyServiceImpl`).
-   [ ] **[Documentation][Low]** Update `ARCHITECTURE.md`:
    *   Align the `KeyService` interface description more closely with the parameters required by its likely dependency (`KeyStorageHandler`, e.g., alias, password, certificate).
    *   Clarify the relationship between `KeyService` and `KeyStorageHandler`.
    *   Clarify the role/status of the generic `DataHandler` interface.

## Testing

-   [ ] **[Testing][Low]** Consider enhancing `VoteServiceImplTest` tallying tests to use ciphertexts generated via the mocked `elGamalCipher` for slightly higher fidelity, although the current approach is reasonable for unit testing.