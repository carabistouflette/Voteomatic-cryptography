# Documentation Technique du Stockage des Clés (PKCS12)

Ce document détaille le fonctionnement interne du `PKCS12KeyStorageHandler`, responsable du stockage et de la récupération sécurisés des paires de clés cryptographiques en utilisant des fichiers keystore au format PKCS#12.

## 1. Initialisation et Configuration

L'instance de [`PKCS12KeyStorageHandler`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:32) est créée via des méthodes factory statiques :

-   [`createFromEnvPassword(String keystorePathStr, String passwordSource)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:57):
    -   Récupère le mot de passe du keystore à partir d'une variable d'environnement spécifiée (par exemple, `env:KEYSTORE_PASSWORD`).
    -   Valide le chemin du fichier keystore et crée les répertoires parents si nécessaire (méthode [`validatePathAndCreateDirs`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:94)).
-   [`createWithPassword(String keystorePathStr, char[] password)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:78):
    -   Utilise un mot de passe fourni directement. Une copie (clone) du tableau de caractères du mot de passe est effectuée pour des raisons de sécurité, et l'original est effacé.
    -   Valide également le chemin et crée les répertoires parents.

Le constructeur privé [`PKCS12KeyStorageHandler(Path keystorePath, char[] password)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:42) stocke le chemin d'accès au fichier keystore et le mot de passe. Un objet `lock` est utilisé pour synchroniser l'accès en écriture au fichier keystore.

## 2. Chargement du Keystore (`loadKeyStore`)

La méthode privée [`loadKeyStore()`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:124) gère le chargement du fichier keystore PKCS#12 :

1.  **Instance de `KeyStore`**: Une instance de `java.security.KeyStore` est obtenue avec le type "PKCS12".
2.  **Chargement du Fichier**:
    -   Si le fichier keystore spécifié par `keystorePath` existe, il est chargé en utilisant un `FileInputStream` et le `keystorePassword`.
    -   Si le fichier n'existe pas, un nouveau keystore vide est initialisé en mémoire (en appelant `keyStore.load(null, keystorePassword)`).
3.  **Gestion des Erreurs**:
    -   Des exceptions comme `KeyStoreException`, `IOException`, `NoSuchAlgorithmException`, `CertificateException` sont interceptées.
    -   Une attention particulière est portée aux `IOException` qui indiquent un mot de passe incorrect (par exemple, message contenant "password was incorrect" ou "mac check failed"), afin de lever une [`DataHandlingException`](src/main/java/com/voteomatic/cryptography/io/DataHandlingException.java:7) plus spécifique.

## 3. Sauvegarde du Keystore (`saveKeyStore`)

La méthode privée [`saveKeyStore(KeyStore keyStore)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:153) sauvegarde l'état actuel du `KeyStore` dans le fichier de manière atomique :

1.  **Fichier Temporaire**: Un fichier temporaire est créé dans le même répertoire que le fichier keystore final (ou dans le répertoire courant si le keystore est à la racine).
2.  **Écriture dans le Fichier Temporaire**: Le contenu du `KeyStore` est écrit dans ce fichier temporaire en utilisant un `FileOutputStream` et le `keystorePassword`.
3.  **Permissions (Best Effort)**: Une tentative est faite pour définir des permissions de fichier restrictives (lecture/écriture pour le propriétaire uniquement, `rw-------`) sur le fichier temporaire en utilisant `Files.setPosixFilePermissions`. Ceci est dépendant de la plateforme.
4.  **Déplacement Atomique**: Le fichier temporaire est ensuite déplacé (renommé) pour remplacer le fichier keystore original. L'option `StandardCopyOption.ATOMIC_MOVE` est utilisée pour garantir que l'opération est atomique, réduisant le risque de corruption du fichier en cas d'échec.
5.  **Nettoyage en Cas d'Erreur**: Si une exception se produit pendant la sauvegarde, le fichier temporaire est supprimé.

## 4. Stockage d'une Paire de Clés (`storeKeyPair`)

La méthode [`storeKeyPair(String alias, KeyPair keyPair, Certificate certificate, char[] password)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:205) stocke une `java.security.KeyPair` et son certificat associé :

1.  **Validation**: Les paramètres `alias`, `keyPair` (et sa clé privée), `certificate`, et le `password` pour l'entrée de clé sont vérifiés.
2.  **Chaîne de Certificats**: Un tableau de certificats `Certificate[]` est créé, contenant généralement uniquement le certificat fourni.
3.  **Synchronisation**: L'opération est synchronisée en utilisant l'objet `lock` pour éviter les accès concurrents au fichier keystore.
4.  **Chargement et Modification**: Le keystore est chargé (via `loadKeyStore`). La méthode `keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, certificateChain)` est appelée pour stocker la clé privée et la chaîne de certificats sous l'alias donné, protégées par le `password` de l'entrée.
5.  **Sauvegarde**: Le keystore modifié est sauvegardé (via `saveKeyStore`).

## 5. Récupération d'une Paire de Clés (`retrieveKeyPair`)

La méthode [`retrieveKeyPair(String alias, char[] password)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:237) récupère une `java.security.KeyPair` :

1.  **Validation**: L'`alias` et le `password` de l'entrée sont vérifiés.
2.  **Chargement**: Le keystore est chargé.
3.  **Vérification de l'Alias**: Il est vérifié si l'alias existe (`keyStore.containsAlias(alias)`) et s'il s'agit bien d'une entrée de clé (`keyStore.isKeyEntry(alias)`).
4.  **Récupération de la Clé Privée**: La clé privée est récupérée en utilisant `keyStore.getKey(alias, password)`. Une `UnrecoverableKeyException` ici indique souvent un mot de passe incorrect pour l'entrée.
5.  **Récupération de la Clé Publique**: Le certificat associé à l'alias est récupéré via `keyStore.getCertificate(alias)`. La clé publique est ensuite extraite de ce certificat (`certificate.getPublicKey()`).
6.  **Retour**: Une nouvelle `java.security.KeyPair` est construite avec la clé publique et la clé privée récupérées.

## 6. Récupération d'une Clé Publique (`getPublicKey`)

La méthode [`getPublicKey(String alias)`](src/main/java/com/voteomatic/cryptography/io/PKCS12KeyStorageHandler.java:297) récupère uniquement la clé publique :

1.  **Validation et Chargement**: L'`alias` est vérifié et le keystore est chargé.
2.  **Vérification de l'Alias**: L'existence de l'alias est vérifiée.
3.  **Récupération du Certificat**: Le certificat est récupéré via `keyStore.getCertificate(alias)`.
4.  **Extraction de la Clé Publique**: La clé publique est extraite du certificat.
5.  **Retour**: La `java.security.PublicKey` est retournée.

Cette classe assure donc une gestion robuste et sécurisée des clés en s'appuyant sur le format standard PKCS#12 et les fonctionnalités de `java.security.KeyStore`.