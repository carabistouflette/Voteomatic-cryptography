# Secure Persistent Key Storage Handler Design

**Task:** Design a secure and persistent implementation of the `KeyStorageHandler` interface to replace the current `InMemoryKeyStorageHandler`.

**Date:** 2025-04-11

## 1. Analysis of Options

Three primary options were considered for persistent and secure key storage:

*   **Encrypted File Storage (Java KeyStore - JCEKS/PKCS12):**
    *   Mechanism: Store key pairs within a password-protected Java KeyStore file.
    *   Pros: Standard Java API, self-contained, file portability, built-in encryption.
    *   Cons: Password management complexity, potential performance issues with large files, requires key type conversion or custom serialization within the store.
*   **Database Storage (with Application-Level Encryption):**
    *   Mechanism: Store serialized key data (especially private keys) in encrypted database columns.
    *   Pros: Leverages existing DB infrastructure, potentially better scaling for many keys, metadata storage.
    *   Cons: Requires DB, implementation complexity (serialization, encryption, Master Key management), security depends heavily on Master Key protection.
*   **Cloud Key Management Service (KMS):**
    *   Mechanism: Utilize services like AWS KMS, Azure Key Vault, Google Cloud KMS.
    *   Pros: High security (often HSM-backed), managed rotation/auditing, scalability.
    *   Cons: Cloud dependency/vendor lock-in, network latency, cost, potential complexity integrating custom key types.

## 2. Evaluation Summary

| Feature                 | Encrypted File (KeyStore) | Database (Encrypted Column) | Cloud KMS                   |
| :---------------------- | :------------------------ | :-------------------------- | :-------------------------- |
| **Security Level**      | Moderate-High (depends on password mgmt) | Moderate-High (depends on MEK mgmt) | High-Very High            |
| **Implementation**      | Moderate                  | High                        | Moderate-High               |
| **Performance**         | OK for moderate keys      | Moderate (DB + crypto)      | Moderate (Network latency)  |
| **Dependencies**        | JRE only                  | DB, JDBC, Crypto libs       | Cloud SDK, Network          |
| **Configuration**       | File path, Password source| DB conn, MEK source         | Cloud creds, Endpoint       |
| **Operational Overhead**| Moderate (Backup, PW rotation) | Moderate (DB backup, MEK rotation) | Low-Moderate (Managed)      |
| **Custom Key Support**  | Needs conversion/serialization | Needs serialization         | Needs secret storage/envelope enc. |

## 3. Proposed Design: Java KeyStore (PKCS12)

*   **Rationale:** This approach provides a good balance of security and implementation complexity for a Java application, leveraging standard JRE features without requiring immediate external infrastructure like a dedicated database or cloud service. It directly addresses the need for persistence and encryption-at-rest. The main challenge is managing the keystore password securely.

## 4. Detailed Design Specification: `PKCS12KeyStorageHandler`

*   **Mechanism:** Implements `KeyStorageHandler` using `java.security.KeyStore` API with the "PKCS12" type.
*   **File:** Stores keys in a single `.p12` file.
*   **Encryption:** The entire keystore file is encrypted using Password-Based Encryption (PBE) derived from a master password.
*   **Password Management:**
    *   The master password **must not** be hardcoded.
    *   It should be sourced securely at runtime via configuration, e.g.:
        *   Environment Variable (Recommended starting point): `KEYSTORE_PASSWORD`
        *   Protected Configuration File Property
        *   External Secret Manager (if available)
*   **Serialization/Storage (`writeData`):**
    1.  Input: `alias` (String), `data` (`byte[]` representing the serialized `KeyPair`). *Assumption: The caller serializes the `KeyPair` object before passing it.*
    2.  Load the PKCS12 KeyStore from the configured path using the master password. Create if not exists.
    3.  **Store as SecretKeyEntry:** Since standard `setKeyEntry` requires `java.security.PrivateKey` and `Certificate[]`, and we have custom ElGamal types, we'll store the raw serialized `KeyPair` bytes.
        *   Wrap the input `data` byte array into a `javax.crypto.spec.SecretKeySpec`: `new SecretKeySpec(data, "RAW")`.
        *   Create a `KeyStore.SecretKeyEntry` with this `SecretKeySpec`.
        *   Store the entry using `keyStore.setEntry(alias, secretKeyEntry, new KeyStore.PasswordProtection(passwordChars))`. The `PasswordProtection` here adds another layer specifically for the entry, using the same master password for simplicity.
    4.  Save the KeyStore back to the file path atomically (e.g., write to temp file, then rename).
*   **Retrieval (`readData`):**
    1.  Input: `alias` (String).
    2.  Load the PKCS12 KeyStore.
    3.  Retrieve the entry using `keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwordChars))`.
    4.  Check if the entry is null (alias not found) -> throw `DataHandlingException`.
    5.  Cast the entry to `KeyStore.SecretKeyEntry`.
    6.  Get the `SecretKey` from the entry.
    7.  Get the raw encoded bytes using `secretKey.getEncoded()`.
    8.  Return these bytes. *Assumption: The caller will deserialize these bytes back into a `KeyPair`.*
*   **Configuration:**
    *   `keystore.path`: Path to the `.p12` file.
    *   `keystore.password.source`: How to get the password (e.g., "env:KEYSTORE_PASSWORD").
*   **Error Handling:**
    *   Wrap `IOException`, `KeyStoreException`, `NoSuchAlgorithmException`, `CertificateException` in `DataHandlingException`.
    *   Handle incorrect password (`IOException: "keystore password was incorrect"` or similar).
    *   Handle alias not found during read.
    *   Implement synchronization (`synchronized` blocks) around KeyStore load/save operations (`writeData`) to ensure thread safety.
*   **Security Best Practices:**
    *   Protect the master password source rigorously.
    *   Use strong file permissions on the `.p12` file (e.g., readable only by the application user).
    *   Ensure regular backups of the `.p12` file and the password source.
    *   Log access attempts (without logging key material).
    *   Use up-to-date, strong PBE algorithms provided by the JCE.