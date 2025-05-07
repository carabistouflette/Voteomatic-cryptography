# Module Preuves à Divulgation Nulle de Connaissance (ZKP)

Ce module implémente divers protocoles de Preuves à Divulgation Nulle de Connaissance (Zero-Knowledge Proofs). Les ZKP permettent à une partie (le prouveur) de prouver à une autre partie (le vérifieur) qu'une déclaration est vraie, sans révéler aucune information au-delà de la validité de la déclaration elle-même.

## Composants

### Interfaces Générales ZKP

-   [`Proof.java`](Proof.java:10): Interface marqueur pour tous les types de preuves ZKP. Indique qu'un objet est une preuve sérialisable.
-   [`Statement.java`](Statement.java:8): Interface représentant la déclaration publique qui doit être prouvée.
-   [`Witness.java`](Witness.java:8): Interface représentant l'information secrète (le témoin) que le prouveur utilise pour construire la preuve.
-   [`ZkpProver.java`](ZkpProver.java:12): Interface générique pour les prouveurs ZKP. Un prouveur génère une [`Proof`](Proof.java:10) pour un [`Statement`](Statement.java:8) donné, en utilisant un [`Witness`](Witness.java:8).
-   [`ZkpVerifier.java`](ZkpVerifier.java:11): Interface générique pour les vérifieurs ZKP. Un vérifieur valide une [`Proof`](Proof.java:10) par rapport à un [`Statement`](Statement.java:8).

### Protocole de Schnorr

Utilisé pour prouver la connaissance d'un logarithme discret.

-   [`SchnorrProof.java`](SchnorrProof.java:10): Représente une preuve générée par le protocole de Schnorr.
-   [`SchnorrProver.java`](SchnorrProver.java:16): Implémente la logique du prouveur pour le protocole de Schnorr.
-   [`SchnorrStatement.java`](SchnorrStatement.java:11): Définit la déclaration publique pour une preuve de Schnorr (par exemple, une clé publique).
-   [`SchnorrVerifier.java`](SchnorrVerifier.java:13): Implémente la logique du vérifieur pour le protocole de Schnorr.
-   [`SchnorrWitness.java`](SchnorrWitness.java:10): Contient la valeur secrète (par exemple, une clé privée) utilisée par le prouveur de Schnorr.

### Protocole Disjonctif de Chaum-Pedersen

Utilisé pour prouver qu'un texte chiffré ElGamal chiffre l'un des deux messages possibles (par exemple, 0 ou 1) sans révéler lequel.

-   [`DisjunctiveChaumPedersenProof.java`](DisjunctiveChaumPedersenProof.java:15): Représente une preuve générée par le protocole disjonctif de Chaum-Pedersen.
-   [`DisjunctiveChaumPedersenProver.java`](DisjunctiveChaumPedersenProver.java:15): Implémente la logique du prouveur pour ce protocole.
-   [`DisjunctiveChaumPedersenStatement.java`](DisjunctiveChaumPedersenStatement.java:16): Définit la déclaration publique, incluant le texte chiffré et les clés publiques.
-   [`DisjunctiveChaumPedersenVerifier.java`](DisjunctiveChaumPedersenVerifier.java:13): Implémente la logique du vérifieur pour ce protocole.
-   [`DisjunctiveChaumPedersenWitness.java`](DisjunctiveChaumPedersenWitness.java:11): Contient l'aléa utilisé pour le chiffrement et la valeur du message réel.

### Utilitaires et Exceptions

-   [`ZkpChallengeUtils.java`](ZkpChallengeUtils.java:12): Fournit des méthodes utilitaires pour calculer les défis (challenges) utilisés dans les protocoles ZKP, assurant la consistance et la sécurité.
-   [`ZkpException.java`](ZkpException.java:7): Exception personnalisée pour les erreurs survenant pendant les opérations ZKP.

## Utilisation

Ce module est crucial pour assurer la confidentialité et la vérifiabilité dans le système de vote. Par exemple, le protocole disjonctif de Chaum-Pedersen peut être utilisé pour prouver qu'un bulletin de vote chiffré contient un vote valide (par exemple, "oui" ou "non") sans révéler le vote lui-même.