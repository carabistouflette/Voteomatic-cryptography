# Module Entrée/Sortie (IO)

Ce module gère les opérations d'entrée/sortie liées aux données cryptographiques, notamment la persistance et la récupération des clés.

## Composants

### Interfaces

-   [`DataHandler.java`](DataHandler.java:8): Interface générique pour la gestion des données. Elle définit les opérations de base pour lire et écrire des objets sérialisables.
-   [`KeyStorageHandler.java`](KeyStorageHandler.java:11): Interface spécialisée pour la gestion du stockage des clés cryptographiques. Elle définit des méthodes pour sauvegarder et charger des paires de clés ([`KeyPair`](../keymanagement/KeyPair.java:11)), des clés publiques ([`PublicKey`](../core/elgamal/PublicKey.java:11)) et des clés privées ([`PrivateKey`](../core/elgamal/PrivateKey.java:8)).

### Classes

-   [`PKCS12KeyStorageHandler.java`](PKCS12KeyStorageHandler.java:32): Implémentation de [`KeyStorageHandler`](KeyStorageHandler.java:11) qui utilise le format de fichier PKCS#12 (généralement avec l'extension `.p12` ou `.pfx`) pour stocker les clés de manière sécurisée. Ce format est un standard pour stocker des clés privées et des certificats X.509, protégés par un mot de passe.
    -   Elle fournit des méthodes pour créer une instance à partir d'un mot de passe fourni directement ou via une variable d'environnement.
    -   Elle gère le chargement et la sauvegarde du keystore PKCS#12.
-   [`DataHandlingException.java`](DataHandlingException.java:7): Exception personnalisée pour les erreurs survenant pendant les opérations de gestion de données (lecture, écriture, chargement de clés, etc.).

## Utilisation

Ce module est essentiel pour la persistance sécurisée des clés cryptographiques. Le [`PKCS12KeyStorageHandler`](PKCS12KeyStorageHandler.java:32) est le composant principal utilisé pour s'assurer que les clés privées sont stockées de manière chiffrée et protégées par un mot de passe, tandis que les clés publiques peuvent être partagées plus librement.