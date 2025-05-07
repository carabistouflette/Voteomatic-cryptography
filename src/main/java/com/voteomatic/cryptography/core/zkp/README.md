# Module Preuves à Divulgation Nulle de Connaissance (ZKP)

Ce module implémente divers protocoles de Preuves à Divulgation Nulle de Connaissance (Zero-Knowledge Proofs). Les ZKP permettent à une partie (le prouveur) de prouver à une autre partie (le vérifieur) qu'une déclaration est vraie, sans révéler aucune information au-delà de la validité de la déclaration elle-même.

## Organisation des Packages

Le module ZKP est structuré en plusieurs packages pour une meilleure organisation :

### Package de Base : `com.voteomatic.cryptography.core.zkp`

Ce package racine contient les éléments fondamentaux et communs à toutes les implémentations de ZKP :

*   **Interfaces Générales ZKP**:
    *   [`Proof.java`](Proof.java:10): Interface marqueur pour tous les types de preuves ZKP. Indique qu'un objet est une preuve sérialisable.
    *   [`Statement.java`](Statement.java:8): Interface représentant la déclaration publique qui doit être prouvée.
    *   [`Witness.java`](Witness.java:8): Interface représentant l'information secrète (le témoin) que le prouveur utilise pour construire la preuve.
    *   [`ZkpProver.java`](ZkpProver.java:12): Interface générique pour les prouveurs ZKP. Un prouveur génère une [`Proof`](Proof.java:10) pour un [`Statement`](Statement.java:8) donné, en utilisant un [`Witness`](Witness.java:8).
    *   [`ZkpVerifier.java`](ZkpVerifier.java:11): Interface générique pour les vérifieurs ZKP. Un vérifieur valide une [`Proof`](Proof.java:10) par rapport à un [`Statement`](Statement.java:8).
*   **Utilitaires et Exceptions**:
    *   [`ZkpChallengeUtils.java`](ZkpChallengeUtils.java:12): Fournit des méthodes utilitaires pour calculer les défis (challenges) utilisés dans les protocoles ZKP, assurant la consistance et la sécurité.
    *   [`ZkpException.java`](ZkpException.java:7): Exception personnalisée pour les erreurs survenant pendant les opérations ZKP.
*   **Classes de base** (si applicable).

### Sous-packages pour Implémentations Spécifiques

Les implémentations concrètes de protocoles ZKP spécifiques se trouvent dans des sous-packages dédiés :

*   **`com.voteomatic.cryptography.core.zkp.chaumpedersen`**:
    *   Contient l'implémentation du protocole **Disjonctif de Chaum-Pedersen**. Ce protocole est typiquement utilisé pour prouver qu'un texte chiffré ElGamal chiffre l'un de deux messages possibles (par exemple, 0 ou 1) sans révéler lequel.
    *   Classes principales : [`DisjunctiveChaumPedersenProof.java`](chaumpedersen/DisjunctiveChaumPedersenProof.java), [`DisjunctiveChaumPedersenProver.java`](chaumpedersen/DisjunctiveChaumPedersenProver.java), [`DisjunctiveChaumPedersenStatement.java`](chaumpedersen/DisjunctiveChaumPedersenStatement.java), [`DisjunctiveChaumPedersenVerifier.java`](chaumpedersen/DisjunctiveChaumPedersenVerifier.java), [`DisjunctiveChaumPedersenWitness.java`](chaumpedersen/DisjunctiveChaumPedersenWitness.java).

*   **`com.voteomatic.cryptography.core.zkp.schnorr`**:
    *   Contient l'implémentation du **protocole de Schnorr**. Ce protocole est utilisé pour prouver la connaissance d'un logarithme discret.
    *   Classes principales : [`SchnorrProof.java`](schnorr/SchnorrProof.java), [`SchnorrProver.java`](schnorr/SchnorrProver.java), [`SchnorrStatement.java`](schnorr/SchnorrStatement.java), [`SchnorrVerifier.java`](schnorr/SchnorrVerifier.java), [`SchnorrWitness.java`](schnorr/SchnorrWitness.java).

## Utilisation

Ce module est crucial pour assurer la confidentialité et la vérifiabilité dans le système de vote. Par exemple, le protocole disjonctif de Chaum-Pedersen peut être utilisé pour prouver qu'un bulletin de vote chiffré contient un vote valide (par exemple, "oui" ou "non") sans révéler le vote lui-même.