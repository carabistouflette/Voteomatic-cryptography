# Documentation Technique : Preuve Disjonctive de Chaum-Pedersen

Ce document explique le fonctionnement de la preuve à divulgation nulle de connaissance (ZKP) disjonctive de Chaum-Pedersen, telle qu'implémentée dans ce projet. Cette preuve est utilisée pour démontrer qu'un texte chiffré ElGamal `(c1, c2)` chiffre l'un des deux messages connus `m0` ou `m1`, sans révéler lequel.

Ceci est crucial dans le contexte du vote pour prouver qu'un bulletin chiffré contient un vote valide (par exemple, "Oui" ou "Non", encodés respectivement en `g^1` et `g^0`) sans révéler le choix de l'électeur.

## Acteurs et Données

-   **Prouveur**: Entité qui génère la preuve (par exemple, le service de vote lors de la création du bulletin).
    -   Connaît le message réel `mv` (où `v` est 0 ou 1), l'aléa `r` utilisé pour chiffrer `mv` en `(c1, c2) = (g^r, mv * h^r)`.
-   **Vérifieur**: Entité qui vérifie la preuve.
    -   Connaît les données publiques : les paramètres de domaine (`p`, `q`, `g`), la clé publique ElGamal `h` (qui est `g^x` où `x` est la clé privée), le texte chiffré `(c1, c2)`, et les deux messages possibles `m0` et `m1`.

## 1. Génération de la Preuve (`DisjunctiveChaumPedersenProver`)

La génération de la preuve (méthode `generateProof` dans [`DisjunctiveChaumPedersenProver.java`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProver.java:27)) suit le protocole standard de preuve OU (OR proof) de Chaum-Pedersen. Supposons que le message réel est `mv` (où `v` est l'index 0 ou 1). Le prouveur va simuler la preuve pour l'autre message `m(1-v)` et construire une preuve réelle pour `mv`.

### Notations :

-   `p`: Grand nombre premier (module).
-   `q`: Ordre du sous-groupe cyclique.
-   `g`: Générateur du sous-groupe.
-   `h`: Clé publique ElGamal (`y` dans la notation standard, `h = g^x mod p`).
-   `(c1, c2)`: Texte chiffré ElGamal, où `c1 = g^r mod p` et `c2 = mv * h^r mod p`.
-   `r`: Aléa utilisé pour le chiffrement ElGamal.
-   `v`: Index du message réel (0 ou 1).
-   `m0, m1`: Les deux messages possibles.
-   `H(...)`: Fonction de hachage cryptographique (par exemple, SHA-256).

### Étapes de Génération :

Le processus dépend de si `v=0` (le message réel est `m0`) ou `v=1` (le message réel est `m1`).

**Cas 1 : Le message réel est `m0` (v=0).**

1.  **Simulation pour `m1` (branche `j=1`)**:
    a.  Choisir aléatoirement `c1_challenge` (le défi simulé pour la branche 1) dans `[0, q-1]`.
    b.  Choisir aléatoirement `r1` (la réponse simulée pour la branche 1) dans `[0, q-1]`.
    c.  Calculer les "commitments" simulés `a1` et `b1` :
        -   `a1 = g^r1 * c1^(-c1_challenge) mod p`
        -   `b1 = h^r1 * (c2/m1)^(-c1_challenge) mod p`
        (Note: `c2/m1` est `c2 * m1^-1 mod p`)

2.  **Preuve réelle pour `m0` (branche `j=0`)**:
    a.  Choisir aléatoirement `w0` (l'aléa de commitment pour la branche 0) dans `[0, q-1]`.
    b.  Calculer les commitments réels `a0` et `b0` :
        -   `a0 = g^w0 mod p`
        -   `b0 = h^w0 mod p`

3.  **Calcul du Défi Global `c`**:
    a.  Le défi global `c` est calculé en hachant la concaténation des valeurs publiques et de tous les commitments :
        `c = H(p | q | g | h | c1 | c2 | m0 | m1 | a0 | b0 | a1 | b1)`
        (La méthode [`ZkpChallengeUtils.computeDisjunctiveChaumPedersenChallenge`](src/main/java/com/voteomatic/cryptography/core/zkp/ZkpChallengeUtils.java:88) gère la sérialisation et le hachage).

4.  **Calcul du Défi Réel `c0`**:
    a.  `c0 = (c - c1_challenge) mod q` (pour que `c0 + c1_challenge = c mod q`).

5.  **Calcul de la Réponse Réelle `r0`**:
    a.  `r0 = (w0 + c0 * r) mod q` (où `r` est l'aléa du chiffrement ElGamal original).

**Cas 2 : Le message réel est `m1` (v=1).**

Le processus est symétrique :

1.  **Simulation pour `m0` (branche `j=0`)**:
    a.  Choisir aléatoirement `c0` (défi simulé) et `r0` (réponse simulée).
    b.  Calculer `a0 = g^r0 * c1^(-c0) mod p` et `b0 = h^r0 * (c2/m0)^(-c0) mod p`.

2.  **Preuve réelle pour `m1` (branche `j=1`)**:
    a.  Choisir aléatoirement `w1`.
    b.  Calculer `a1 = g^w1 mod p` et `b1 = h^w1 mod p`.

3.  **Calcul du Défi Global `c`**:
    a.  `c = H(p | q | g | h | c1 | c2 | m0 | m1 | a0 | b0 | a1 | b1)`.

4.  **Calcul du Défi Réel `c1_challenge`**:
    a.  `c1_challenge = (c - c0) mod q`.

5.  **Calcul de la Réponse Réelle `r1`**:
    a.  `r1 = (w1 + c1_challenge * r) mod q`.

### Résultat de la Preuve :

La preuve générée est un objet [`DisjunctiveChaumPedersenProof`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenProof.java:15) contenant les 8 valeurs : `(a0, b0, c0, r0, a1, b1, c1_challenge, r1)`.

## 2. Vérification de la Preuve (`DisjunctiveChaumPedersenVerifier`)

La vérification (méthode `verifyProof` dans [`DisjunctiveChaumPedersenVerifier.java`](src/main/java/com/voteomatic/cryptography/core/zkp/DisjunctiveChaumPedersenVerifier.java:21)) consiste à s'assurer que les équations de la preuve tiennent.

### Étapes de Vérification :

1.  **Recalcul du Défi Global `calculated_c`**:
    a.  Le vérifieur recalcule le défi global `calculated_c` en utilisant les mêmes valeurs publiques et les commitments `(a0, b0, a1, b1)` fournis dans la preuve, et la même fonction de hachage `H`.
    `calculated_c = H(p | q | g | h | c1 | c2 | m0 | m1 | a0 | b0 | a1 | b1)`.

2.  **Vérification de la Consistance du Défi**:
    a.  Vérifier que `calculated_c == (c0 + c1_challenge) mod q`. Si ce n'est pas le cas, la preuve est invalide.

3.  **Vérification des Équations pour la Branche 0**:
    a.  Vérifier que `g^r0 == a0 * c1^c0 mod p`.
    b.  Vérifier que `h^r0 == b0 * (c2/m0)^c0 mod p`.
    Si l'une de ces équations est fausse, la preuve est invalide.

4.  **Vérification des Équations pour la Branche 1**:
    a.  Vérifier que `g^r1 == a1 * c1^c1_challenge mod p`.
    b.  Vérifier que `h^r1 == b1 * (c2/m1)^c1_challenge mod p`.
    Si l'une de ces équations est fausse, la preuve est invalide.

### Résultat de la Vérification :

Si toutes les vérifications (consistance du défi et les quatre équations de commitment) passent, la preuve est considérée comme valide, et le vérifieur retourne `true`. Sinon, il retourne `false`.

Cette preuve garantit que le texte chiffré `(c1, c2)` est bien le chiffré de `m0` OU de `m1` en utilisant l'aléa `r` (pour la branche réelle), sans révéler pour quelle branche la preuve est "réelle" et pour laquelle elle est "simulée".