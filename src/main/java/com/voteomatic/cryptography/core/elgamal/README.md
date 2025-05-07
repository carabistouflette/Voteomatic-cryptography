# Module ElGamal

Ce module implémente le schéma de chiffrement ElGamal. Il fournit les classes nécessaires pour générer des clés, chiffrer et déchiffrer des données en utilisant l'algorithme ElGamal.

## Composants

### Interfaces

-   [`ElGamalCipher.java`](ElGamalCipher.java:9): Définit le contrat pour les opérations de chiffrement et de déchiffrement ElGamal.

### Classes

-   [`ElGamalCipherImpl.java`](ElGamalCipherImpl.java:12): Implémentation concrète de l'interface [`ElGamalCipher`](ElGamalCipher.java:9). Elle gère la logique de chiffrement d'un message avec une clé publique et de déchiffrement d'un texte chiffré avec une clé privée.
-   [`Ciphertext.java`](Ciphertext.java:11): Représente un texte chiffré ElGamal, généralement composé de deux composantes (c1, c2). Fournit des méthodes pour manipuler les textes chiffrés, comme la multiplication homomorphe.
-   [`EncryptionResult.java`](EncryptionResult.java:10): Encapsule le résultat d'une opération de chiffrement ElGamal. Contient typiquement le [`Ciphertext`](Ciphertext.java:11) et l'aléa utilisé durant le chiffrement.
-   [`PrivateKey.java`](PrivateKey.java:8): Représente une clé privée ElGamal. Elle est utilisée pour le déchiffrement. Contient les paramètres du domaine et la valeur secrète 'x'.
-   [`PublicKey.java`](PublicKey.java:11): Représente une clé publique ElGamal. Elle est utilisée pour le chiffrement. Contient les paramètres du domaine et la valeur publique 'y'.

## Utilisation

Ce module est fondamental pour les opérations cryptographiques nécessitant un chiffrement asymétrique. Il est utilisé par d'autres modules pour sécuriser les votes et d'autres données sensibles.