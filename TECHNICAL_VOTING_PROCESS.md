# Documentation Technique du Processus de Vote

Ce document détaille le fonctionnement interne des opérations cryptographiques clés du système de vote, telles qu'implémentées principalement dans `VoteServiceImpl`.

## 1. Création d'un Vote Chiffré (`castVote`)

Le processus de création d'un vote chiffré et de sa preuve de validité se déroule comme suit (voir la méthode `castVote` dans [`VoteServiceImpl.java`](src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java:75)):

### 1.1. Validation et Encodage du Vote

1.  **Validation des Entrées**: Les informations d'identification de l'électeur ([`VoterCredentials`](src/main/java/com/voteomatic/cryptography/voting/VoterCredentials.java:12)), le vote en clair ([`Vote`](src/main/java/com/voteomatic/cryptography/voting/Vote.java:10)), et la clé publique de l'élection ([`PublicKey`](src/main/java/com/voteomatic/cryptography/core/elgamal/PublicKey.java:11)) sont vérifiés pour s'assurer qu'ils ne sont pas nuls.
2.  **Encodage du Vote**: L'option de vote (chaîne de caractères, par exemple, "Yes" ou "No") est convertie en un élément du groupe cyclique utilisé par ElGamal.
    -   Si le vote est "Yes", le message est encodé comme `g^1 mod p` (où `g` est le générateur et `p` le module des [`DomainParameters`](src/main/java/com/voteomatic/cryptography/core/DomainParameters.java:1)).
    -   Si le vote est "No", le message est encodé comme `g^0 mod p` (c'est-à-dire `1`).
    -   Toute autre option de vote lève une [`VotingException`](src/main/java/com/voteomatic/cryptography/voting/VotingException.java:7).

### 1.2. Chiffrement ElGamal

1.  **Chiffrement**: Le message encodé ( `g^0` ou `g^1`) est chiffré en utilisant l'algorithme ElGamal et la clé publique de l'élection.
    -   L'opération de chiffrement est effectuée par l'instance de [`ElGamalCipher`](src/main/java/com/voteomatic/cryptography/core/elgamal/ElGamalCipher.java:9) (par exemple, [`ElGamalCipherImpl`](src/main/java/com/voteomatic/cryptography/core/elgamal/ElGamalCipherImpl.java:12)).
    -   Le résultat est un objet [`EncryptionResult`](src/main/java/com/voteomatic/cryptography/core/elgamal/EncryptionResult.java:10) qui contient :
        -   Le texte chiffré ([`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11)), typiquement une paire `(c1, c2)`.
        -   L'aléa `r` (un entier `BigInteger`) utilisé pendant le chiffrement. Cet aléa est crucial pour la preuve ZKP.

### 1.3. Préparation et Génération de la Preuve ZKP (Disjonctive Chaum-Pedersen)

Pour prouver que le texte chiffré contient bien un vote valide (soit "Yes", soit "No") sans révéler lequel, une preuve disjonctive de Chaum-Pedersen est générée.

1.  **Définition des Messages Possibles**:
    -   `m0 = g^0` (représentant "No")
    -   `m1 = g^1` (représentant "Yes")
2.  **Construction du `Statement`**: Un objet [`DisjunctiveChaumPedersenStatement`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenStatement.java:16) est créé. Il contient les informations publiques nécessaires à la vérification :
    -   La clé publique de l'élection ([`PublicKey`](src/main/java/com/voteomatic/cryptography/core/elgamal/PublicKey.java:11)).
    -   Le texte chiffré du vote ([`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11)).
    -   Les deux messages possibles encodés (`m0` et `m1`).
3.  **Construction du `Witness`**: Un objet [`DisjunctiveChaumPedersenWitness`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenWitness.java:11) est créé. Il contient les informations secrètes que seul le prouveur (l'électeur, ou le service agissant en son nom) connaît :
    -   L'aléa `r` utilisé lors du chiffrement ElGamal.
    -   L'index `voteIndex` du message réellement chiffré (0 si "No", 1 si "Yes").
4.  **Génération de la Preuve**:
    -   L'instance de [`ZkpProver`](src/main/java/com/voteomatic/cryptography/core/zkp/ZkpProver.java:12) (configurée pour être un [`DisjunctiveChaumPedersenProver`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProver.java:15)) est utilisée pour générer la [`Proof`](src/main/java/com/voteomatic/cryptography/core/zkp/Proof.java:10) (une instance de [`DisjunctiveChaumPedersenProof`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProof.java:15)) à partir du `Statement` et du `Witness`.

### 1.4. Résultat

Le processus retourne un objet [`EncryptedVote`](src/main/java/com/voteomatic/cryptography/voting/EncryptedVote.java:13), qui encapsule :
-   Le [`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11) du vote.
-   La [`DisjunctiveChaumPedersenProof`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProof.java:15) de validité.

## 2. Vérification d'un Vote Chiffré (`verifyVote`)

La méthode `verifyVote` dans [`VoteServiceImpl.java`](src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java:220) permet de vérifier la validité d'un [`EncryptedVote`](src/main/java/com/voteomatic/cryptography/voting/EncryptedVote.java:13) individuel en utilisant sa preuve ZKP.

1.  **Validation des Entrées**: Le `Statement` et la `Proof` fournis sont vérifiés. Il est attendu qu'ils soient des instances de [`DisjunctiveChaumPedersenStatement`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenStatement.java:16) et [`DisjunctiveChaumPedersenProof`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProof.java:15) respectivement.
2.  **Vérification de la Preuve**:
    -   L'instance de [`ZkpVerifier`](src/main/java/com/voteomatic/cryptography/core/zkp/ZkpVerifier.java:11) (configurée pour être un [`DisjunctiveChaumPedersenVerifier`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenVerifier.java:13)) est utilisée pour vérifier la `Proof` par rapport au `Statement`.
    -   La méthode `verifyProof` du vérifieur retourne `true` si la preuve est valide, `false` sinon.

## 3. Décompte des Votes (`tallyVotes`)

La méthode `tallyVotes` dans [`VoteServiceImpl.java`](src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java:147) utilise la propriété homomorphe additive du cryptosystème ElGamal pour sommer les votes chiffrés, puis déchiffre le résultat agrégé.

### 3.1. Précalcul des Logarithmes Discrets (Constructeur)

Lors de l'initialisation de [`VoteServiceImpl`](src/main/java/com/voteomatic/cryptography/voting/VoteServiceImpl.java:34), une table de recherche pour les logarithmes discrets est précalculée (méthode `precomputeDiscreteLogMap`).
-   Pour `i` allant de 0 à `MAX_VOTES` (une limite supérieure sur le nombre de votes attendus), la valeur `g^i mod p` est calculée et stockée dans une `Map` associant `g^i` à `i`.
-   Ceci permet de retrouver rapidement la valeur `k` à partir de `g^k` lors du déchiffrement final du total.

### 3.2. Agrégation Homomorphe

1.  **Initialisation**: Un [`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11) accumulateur est initialisé à l'élément neutre pour la multiplication ElGamal, c'est-à-dire `(1, 1)`.
2.  **Multiplication des Textes Chiffrés**: Pour chaque [`EncryptedVote`](src/main/java/com/voteomatic/cryptography/voting/EncryptedVote.java:13) dans la liste :
    -   Le [`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11) du vote courant est récupéré.
    -   Ce texte chiffré est multiplié (homomorphiquement) avec le texte chiffré accumulateur. La multiplication de deux textes chiffrés ElGamal `(a,b)` et `(c,d)` donne `(a*c mod p, b*d mod p)`. Si `E(m1)` et `E(m2)` sont les chiffrés de `m1` et `m2`, alors `E(m1) * E(m2) = E(m1 * m2)`. Dans notre cas, les messages sont `g^0` ou `g^1`. La multiplication des messages correspond à l'addition des exposants: `g^v1 * g^v2 = g^(v1+v2)`.
    -   Le résultat de cette multiplication devient le nouveau contenu du texte chiffré accumulateur.

### 3.3. Déchiffrement et Résultat

1.  **Déchiffrement Final**: Une fois tous les votes agrégés, le [`Ciphertext`](src/main/java/com/voteomatic/cryptography/core/elgamal/Ciphertext.java:11) accumulateur final est déchiffré en utilisant la clé privée de l'élection ([`PrivateKey`](src/main/java/com/voteomatic/cryptography/core/elgamal/PrivateKey.java:8)) et l'instance de [`ElGamalCipher`](src/main/java/com/voteomatic/cryptography/core/elgamal/ElGamalCipher.java:9).
    -   Le résultat du déchiffrement est `M_total = g^k mod p`, où `k` est la somme des exposants des votes individuels (c'est-à-dire le nombre total de votes "Yes", puisque "No" est `g^0` et "Yes" est `g^1`).
2.  **Récupération du Nombre de Votes**:
    -   La valeur `k` (le nombre de votes "Yes") est retrouvée en utilisant la table de logarithmes discrets précalculée (`discreteLogMap`). On recherche `M_total` dans la map pour obtenir `k`.
    -   Si `M_total` n'est pas trouvé dans la map, cela peut indiquer une erreur ou que le nombre de votes a dépassé `MAX_VOTES`. Une [`VotingException`](src/main/java/com/voteomatic/cryptography/voting/VotingException.java:7) est levée.
3.  **Retour**: La méthode retourne `k` sous forme de `BigInteger`, représentant le nombre total de votes "Yes".