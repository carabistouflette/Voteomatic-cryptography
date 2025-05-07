# Module de Vote (Voting)

Ce module gère la logique métier spécifique au processus de vote électronique. Il s'appuie sur les modules cryptographiques de bas niveau (ElGamal, ZKP) pour assurer la sécurité et la confidentialité des votes.

## Composants

### Interfaces

-   [`VoteService.java`](VoteService.java:15): Définit le contrat pour les services liés au vote. Les opérations typiques incluent la création d'un bulletin de vote chiffré à partir d'un vote en clair, la vérification de la validité d'un bulletin chiffré, et potentiellement le décompte des votes (bien que le décompte puisse être une responsabilité séparée selon l'architecture).

### Classes

-   [`VoteServiceImpl.java`](VoteServiceImpl.java:16): Implémentation concrète de l'interface [`VoteService`](VoteService.java:15).
    -   Utilise [`ElGamalCipher`](../core/elgamal/ElGamalCipher.java:9) pour chiffrer les votes.
    -   Utilise des prouveurs et vérifieurs ZKP (par exemple, [`DisjunctiveChaumPedersenProver`](../core/zkp/DisjunctiveChaumPedersenProver.java:15) et [`DisjunctiveChaumPedersenVerifier`](../core/zkp/DisjunctiveChaumPedersenVerifier.java:13)) pour générer et vérifier des preuves que le vote chiffré est valide (par exemple, qu'il chiffre bien un "0" ou un "1" dans un vote binaire) sans révéler le vote lui-même.
    -   Peut inclure une logique pour précalculer une table de logarithmes discrets (baby-step giant-step) pour accélérer le déchiffrement lors du décompte, si applicable.
-   [`EncryptedVote.java`](EncryptedVote.java:13): Représente un bulletin de vote chiffré. Il contient typiquement le [`Ciphertext`](../core/elgamal/Ciphertext.java:11) du vote et une [`Proof`](../core/zkp/Proof.java:10) ZKP attestant de sa validité.
-   [`Vote.java`](Vote.java:10): Représente un vote en clair, avant chiffrement. Contient l'option sélectionnée par l'électeur.
-   [`VoterCredentials.java`](VoterCredentials.java:12): Représente les informations d'identification d'un électeur, comme un identifiant unique. Peut être utilisé pour lier un vote à un électeur de manière anonymisée ou pseudonymisée.
-   [`VotingException.java`](VotingException.java:7): Exception personnalisée pour les erreurs survenant pendant le processus de vote (par exemple, échec du chiffrement, preuve de validité incorrecte).

## Utilisation

Ce module est au cœur de la fonctionnalité de vote de l'application.
1.  Un électeur soumet un [`Vote`](Vote.java:10) en clair.
2.  Le [`VoteService`](VoteService.java:15) utilise la clé publique de l'élection pour chiffrer ce vote, produisant un [`Ciphertext`](../core/elgamal/Ciphertext.java:11).
3.  Le [`VoteService`](VoteService.java:15) génère également une [`Proof`](../core/zkp/Proof.java:10) (par exemple, une preuve disjonctive de Chaum-Pedersen) pour démontrer que le vote chiffré est bien formé et correspond à une option valide, sans révéler l'option choisie.
4.  Le [`Ciphertext`](../core/elgamal/Ciphertext.java:11) et la [`Proof`](../core/zkp/Proof.java:10) sont regroupés dans un [`EncryptedVote`](EncryptedVote.java:13) qui est ensuite stocké ou transmis.
5.  Lors du décompte, les [`EncryptedVote`](EncryptedVote.java:13)s sont vérifiés (leurs preuves sont validées) puis déchiffrés en utilisant la clé privée de l'élection.