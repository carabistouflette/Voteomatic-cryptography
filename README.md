# Vote-O-Matic Cryptography Library

Bienvenue dans la bibliothèque cryptographique de Vote-O-Matic. Ce projet fournit les briques de base pour un système de vote électronique sécurisé, en mettant l'accent sur la confidentialité et la vérifiabilité grâce à des techniques cryptographiques avancées.

## Architecture Générale

La bibliothèque est organisée en plusieurs modules principaux, chacun responsable d'un aspect spécifique du système cryptographique :

-   **Core Cryptography (`core`)**: Contient les implémentations des algorithmes cryptographiques fondamentaux.
    -   [**ElGamal (`core/elgamal`)**](src/main/java/com/voteomatic/cryptography/core/elgamal/README.md): Implémentation du schéma de chiffrement asymétrique ElGamal, utilisé pour chiffrer les votes.
    -   [**Zero-Knowledge Proofs (ZKP) (`core/zkp`)**](src/main/java/com/voteomatic/cryptography/core/zkp/README.md): Implémentations de protocoles de preuves à divulgation nulle de connaissance, comme le protocole de Schnorr et le protocole disjonctif de Chaum-Pedersen. Ces preuves permettent de vérifier la validité d'un vote chiffré sans le déchiffrer.

-   [**Input/Output (`io`)**](src/main/java/com/voteomatic/cryptography/io/README.md): Gère la persistance et la récupération des données cryptographiques, notamment le stockage sécurisé des clés (par exemple, via des keystores PKCS#12).

-   [**Key Management (`keymanagement`)**](src/main/java/com/voteomatic/cryptography/keymanagement/README.md): Responsable de la génération, du stockage et de la récupération des paires de clés cryptographiques ElGamal.

-   [**Security Utilities (`securityutils`)**](src/main/java/com/voteomatic/cryptography/securityutils/README.md): Fournit des utilitaires cryptographiques essentiels tels que la génération de nombres aléatoires sécurisés, les fonctions de hachage (SHA-256) et les mécanismes de signature numérique.

-   [**Voting Logic (`voting`)**](src/main/java/com/voteomatic/cryptography/voting/README.md): Orchestre le processus de vote, en utilisant les modules cryptographiques pour chiffrer les votes et générer des preuves de validité.

## Fonctionnalités Clés

-   **Chiffrement des Votes**: Les votes sont chiffrés en utilisant le cryptosystème ElGamal pour garantir la confidentialité.
-   **Vérifiabilité**: Des preuves à divulgation nulle de connaissance sont utilisées pour permettre à quiconque de vérifier que chaque vote chiffré est valide (par exemple, qu'il correspond à une option autorisée) sans pour autant révéler le contenu du vote.
-   **Gestion Sécurisée des Clés**: Les clés cryptographiques sont gérées et stockées de manière sécurisée.

## Structure du Projet

```
.
├── pom.xml                 # Dépendances et configuration Maven
├── src
│   ├── main
│   │   └── java
│   │       └── com
│   │           └── voteomatic
│   │               └── cryptography
│   │                   ├── core
│   │                   │   ├── elgamal/      # Implémentation ElGamal
│   │                   │   │   └── README.md
│   │                   │   └── zkp/          # Preuves à Divulgation Nulle
│   │                   │       └── README.md
│   │                   ├── io/               # Gestion Entrée/Sortie (clés, etc.)
│   │                   │   └── README.md
│   │                   ├── keymanagement/    # Gestion des clés
│   │                   │   └── README.md
│   │                   ├── securityutils/    # Utilitaires (hash, signature)
│   │                   │   └── README.md
│   │                   └── voting/           # Logique de vote
│   │                       └── README.md
│   └── test                  # Tests unitaires et d'intégration
└── README.md               # Ce fichier
```

## Pour Commencer

Consultez les `README.md` spécifiques à chaque module pour une description détaillée de leurs composants et de leur utilisation.

-   [Documentation du module `core/elgamal`](src/main/java/com/voteomatic/cryptography/core/elgamal/README.md)
-   [Documentation du module `core/zkp`](src/main/java/com/voteomatic/cryptography/core/zkp/README.md)
-   [Documentation du module `io`](src/main/java/com/voteomatic/cryptography/io/README.md)
-   [Documentation du module `keymanagement`](src/main/java/com/voteomatic/cryptography/keymanagement/README.md)
-   [Documentation du module `securityutils`](src/main/java/com/voteomatic/cryptography/securityutils/README.md)
-   [Documentation du module `voting`](src/main/java/com/voteomatic/cryptography/voting/README.md)

---

Ce projet vise à fournir une base solide et compréhensible pour la cryptographie électorale.