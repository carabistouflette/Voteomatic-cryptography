# Module Gestion des Clés (Key Management)

Ce module est responsable de la génération, du stockage et de la récupération des paires de clés cryptographiques ElGamal. Il s'interface avec le module `io` pour la persistance des clés.

## Composants

### Interfaces

-   [`KeyService.java`](KeyService.java:9): Définit le contrat pour les services de gestion de clés. Les opérations incluent la génération de nouvelles paires de clés, la sauvegarde et le chargement de paires de clés, de clés publiques et de clés privées individuelles, ainsi que la récupération d'une clé publique par son identifiant.

### Classes

-   [`KeyServiceImpl.java`](KeyServiceImpl.java:45): Implémentation concrète de l'interface [`KeyService`](KeyService.java:9).
    -   Utilise un [`KeyStorageHandler`](../io/KeyStorageHandler.java:11) (par exemple, [`PKCS12KeyStorageHandler`](../io/PKCS12KeyStorageHandler.java:32)) pour interagir avec le support de stockage des clés.
    -   Gère la génération de paires de clés ElGamal en utilisant les paramètres de domaine fournis.
    -   Implémente la logique pour convertir les clés entre le format interne de l'application (par exemple, [`com.voteomatic.cryptography.core.elgamal.PublicKey`](../core/elgamal/PublicKey.java:11)) et les formats JCE (Java Cryptography Extension) pour le stockage et la génération de certificats.
    -   Peut générer des certificats auto-signés X.509 pour encapsuler les clés publiques, ce qui peut être utile pour certains scénarios d'échange de clés ou d'intégration.
-   [`KeyPair.java`](KeyPair.java:8): Une classe conteneur simple pour associer une [`PublicKey`](../core/elgamal/PublicKey.java:11) ElGamal à sa [`PrivateKey`](../core/elgamal/PrivateKey.java:8) correspondante.
-   [`KeyManagementException.java`](KeyManagementException.java:7): Exception personnalisée pour les erreurs qui se produisent pendant les opérations de gestion de clés (par exemple, échec de la génération, du chargement ou de la sauvegarde d'une clé).

## Utilisation

Ce module est central pour initialiser et maintenir l'infrastructure cryptographique du système. Avant que toute opération de chiffrement ou de déchiffrement puisse avoir lieu, les clés appropriées doivent être générées et stockées de manière sécurisée, ou chargées à partir d'un stockage existant. Le `KeyService` fournit une abstraction pour ces opérations.