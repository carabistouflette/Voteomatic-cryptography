# Module Utilitaires de Sécurité (Security Utilities)

Ce module fournit diverses fonctionnalités cryptographiques de base et des utilitaires de sécurité qui sont utilisés à travers l'application. Cela inclut la génération de nombres aléatoires sécurisés, le hachage de données et la création/vérification de signatures numériques.

## Composants

### Interfaces

-   [`DigitalSignature.java`](DigitalSignature.java:7): Définit le contrat pour les opérations de signature numérique. Cela inclut la signature de données avec une clé privée et la vérification d'une signature avec une clé publique.
-   [`HashAlgorithm.java`](HashAlgorithm.java:7): Définit le contrat pour les algorithmes de hachage. Les opérations incluent le calcul du hachage d'un tableau d'octets ou d'un `BigInteger`.
-   [`PrivateSigningKey.java`](PrivateSigningKey.java:8): Interface marqueur pour les clés privées utilisées pour la signature numérique.
-   [`PublicVerificationKey.java`](PublicVerificationKey.java:8): Interface marqueur pour les clés publiques utilisées pour la vérification de signature numérique.
-   [`SecureRandomGenerator.java`](SecureRandomGenerator.java:11): Définit le contrat pour la génération de nombres et d'octets aléatoires sécurisés. Essentiel pour de nombreuses opérations cryptographiques comme la génération de clés et d'aléas.

### Classes

-   [`DigitalSignatureImpl.java`](DigitalSignatureImpl.java:15): Implémentation de [`DigitalSignature`](DigitalSignature.java:7). Utilise les classes `Signature` de JCE (Java Cryptography Extension) pour effectuer les opérations de signature et de vérification. Elle peut être configurée avec différents algorithmes de signature (par exemple, "SHA256withRSA", "SHA256withDSA").
-   [`PrivateSigningKeyImpl.java`](PrivateSigningKeyImpl.java:7): Implémentation concrète de [`PrivateSigningKey`](PrivateSigningKey.java:8), encapsulant une `java.security.PrivateKey`.
-   [`PublicVerificationKeyImpl.java`](PublicVerificationKeyImpl.java:9): Implémentation concrète de [`PublicVerificationKey`](PublicVerificationKey.java:8), encapsulant une `java.security.PublicKey`.
-   [`SecureRandomGeneratorImpl.java`](SecureRandomGeneratorImpl.java:7): Implémentation de [`SecureRandomGenerator`](SecureRandomGenerator.java:11). Utilise `java.security.SecureRandom` pour fournir des nombres aléatoires cryptographiquement forts.
-   [`SHA256HashAlgorithm.java`](SHA256HashAlgorithm.java:7): Implémentation de [`HashAlgorithm`](HashAlgorithm.java:7) utilisant l'algorithme SHA-256.
-   [`SecurityUtilException.java`](SecurityUtilException.java:7): Exception personnalisée pour les erreurs survenant lors de l'utilisation des utilitaires de sécurité (par exemple, algorithme non supporté, échec de la signature/vérification).

## Utilisation

Ce module fournit des blocs de construction cryptographiques fondamentaux.
-   Le [`SecureRandomGenerator`](SecureRandomGenerator.java:11) est utilisé partout où des nombres aléatoires imprévisibles sont nécessaires, par exemple dans le chiffrement ElGamal et les protocoles ZKP.
-   Les algorithmes de hachage comme [`SHA256HashAlgorithm`](SHA256HashAlgorithm.java:7) sont utilisés pour créer des empreintes de données, souvent comme étape préliminaire à la signature numérique ou dans les calculs de défi ZKP.
-   Les fonctionnalités de [`DigitalSignature`](DigitalSignature.java:7) sont utilisées pour assurer l'authenticité et l'intégrité des messages ou des données.