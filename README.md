# CryptoApp — Plateforme de Cryptographie Avancée

**CryptoApp** est une plateforme web éducative dédiée à l'apprentissage et à la manipulation des algorithmes de cryptographie. Développée dans le cadre du cours de **Pr. Asmae EL KASSIRI**, cette application implémente de manière **pure** (sans bibliothèques cryptographiques externes) l'ensemble des algorithmes de chiffrement symétriques et asymétriques majeurs.

---

## Table des matières

- [Algorithmes implémentés](#algorithmes-implémentés)
- [Stack technologique](#stack-technologique)
- [Installation et démarrage](#installation-et-démarrage)
- [Structure du projet](#structure-du-projet)
- [Comptes par défaut](#comptes-par-défaut)
- [Utilisation](#utilisation)
- [Sécurité des mots de passe](#sécurité-des-mots-de-passe)
- [Documentation des algorithmes](#documentation-des-algorithmes)
- [Dépannage](#dépannage)
- [Équipe](#équipe)

---

## Algorithmes implémentés

### Cryptographie symétrique (8 algorithmes)

| Algorithme | Type | Statut | Description |
|------------|------|--------|-------------|
| Code César | Substitution | Ok | Décalage alphabétique simple |
| Vigenère | Poly-alphabétique | Ok | Chiffrement par clé répétée |
| Vernam (OTP) | XOR | Ok | Masque jetable, sécurité parfaite |
| RC4 | Chiffrement par flot | Ok | Stream cipher à usage pédagogique |
| DES | Chiffrement par bloc (64 bits) | Ok | Réseau de Feistel, 16 rondes |
| DES-CBC | Mode CBC | Ok | Cipher Block Chaining |
| DES-CFB | Mode CFB | Ok | Cipher Feedback |
| AES-128 | Chiffrement par bloc (128 bits) | Ok | Standard NIST, 10 rondes |

### Cryptographie asymétrique (3 algorithmes)

| Algorithme | Problème mathématique | Statut | Description |
|------------|----------------------|--------|-------------|
| RSA | Factorisation | Ok | Rivest-Shamir-Adleman |
| ElGamal | Logarithme discret | Ok | Chiffrement probabiliste |
| EC-ElGamal | Logarithme discret elliptique | Ok | Version sur courbe secp256k1 |

### Fonctionnalités supplémentaires

- Hachage des mots de passe : SHA-256
- Interface administrateur : Gestion complète des utilisateurs
- Changement de mot de passe : Sécurisé avec validation
- Indicatrice de force pour les mots de passe

---

## Stack technologique

| Composant | Technologie |
|-----------|-------------|
| Backend | Python 3.10 + Flask 2.3 |
| Base de données | SQLite 3 |
| Frontend | HTML5 + Bootstrap 5.3 |
| Icônes | Bootstrap Icons |
| Police | Inter (Google Fonts) |
| Cryptographie | Implémentation maison pure |

---

## Installation et démarrage

### Prérequis

| Outil | Version |
|-------|---------|
| Python | 3.10 ou supérieur |
| pip | Dernière version |
| Navigateur | Moderne (Chrome, Firefox, Edge) |
| Ports libres | 5000 (Flask) |

### 1. Cloner le dépôt

git clone https://github.com/mohamedkafando185-blip/CryptoApp.git \
cd CryptoApp

### 2. Installer les dépendances

pip install flask

Aucune autre dépendance n'est requise — l'implémentation est pure Python.

### 3. Lancer l'application

python app.py

### 4. Accéder à l'application

| Service | URL |
|---------|-----|
| Application | http://localhost:5000 |

---

## Structure du projet

CryptoApp/\
├── app.py                      # Application Flask principale\
├── crypto_algorithms.py        # Implémentation pure des algorithmes\
├── cryptoapp.db                # Base de données SQLite (autocréée)\
├── templates/\
│   ├── login.html              # Page de connexion\
│   ├── register.html           # Page d'inscription\
│   ├── dashboard.html          # Dashboard utilisateur\
│   └── admin_dashboard.html    # Dashboard administrateur\
└── README.md

---

## Comptes par défaut

| Rôle | Nom d'utilisateur | Email | Mot de passe |
|------|-------------------|-------|--------------|
| Administrateur | admin | admin@cryptoapp.com | Admin@1234 |

Important : Le compte administrateur est automatiquement créé au premier démarrage. Changez impérativement le mot de passe en production.

### Créer un utilisateur standard

1. Cliquez sur "Créer un compte" sur la page de connexion
2. Remplissez le formulaire d'inscription
3. Connectez-vous avec vos nouveaux identifiants

---

## Utilisation

### Interface utilisateur

L'interface est organisée en deux sections principales :

- Cryptographie symétrique : César, Vigenère, Vernam, RC4, DES, AES
- Cryptographie asymétrique : RSA, ElGamal, EC-ElGamal

### Utilisation d'un algorithme

1. Sélectionnez l'algorithme dans le menu latéral
2. Saisissez le message à chiffrer/déchiffrer
3. Saisissez les paramètres (clé, décalage, etc.)
4. Cliquez sur "Chiffrer" ou "Déchiffrer"
5. Le résultat s'affiche instantanément

### Génération de clés (asymétrique)

Pour RSA, ElGamal et EC-ElGamal :

1. Cliquez sur "Générer les clés" dans la section correspondante
2. Les clés publique et privée sont automatiquement affichées
3. Utilisez la clé publique pour chiffrer, la clé privée pour déchiffrer

### Changement de mot de passe

1. Cliquez sur "Changer mon mot de passe" dans le menu latéral
2. Saisissez l'ancien mot de passe
3. Saisissez le nouveau mot de passe (minimum 6 caractères)
4. Confirmez le nouveau mot de passe
5. Cliquez sur "Changer le mot de passe"

---

## Sécurité des mots de passe

- Hachage : SHA-256 (pas de stockage en clair)
- Longueur minimale : 6 caractères
- Indicateur de force :
  - Très faible : 1 critère
  - Moyen : 2-3 critères
  - Fort : 4 critères
  - Très fort : 5 critères (lettres + chiffres + symboles + majuscules + longueur 10+)

---

## Documentation des algorithmes

### Code César
Décalage circulaire des lettres et des chiffres. Formule : C = (M + k) mod 26.

### Vigenère
Substitution polyalphabétique utilisant une clé répétée. Formule : C_i = (M_i + K_(i mod |K|)) mod 26.

### Vernam (One-Time Pad)
XOR entre le message et une clé aléatoire de même longueur. Sécurité parfaite si la clé est vraiment aléatoire et non réutilisée.

### RC4
Chiffrement par flot utilisant un KSA (Key Scheduling Algorithm) et un PRGA (Pseudo-Random Generation Algorithm).

### DES (Data Encryption Standard)
Réseau de Feistel sur blocs de 64 bits avec 16 rondes. Tables S-Box et permutations standard.

### Modes CBC et CFB
- CBC : Cipher Block Chaining — chaque bloc dépend du précédent
- CFB : Cipher Feedback — mode flot utilisant le bloc précédent

### AES-128 (Advanced Encryption Standard)
Chiffrement par blocs de 128 bits, 10 rondes, S-Box, MixColumns, ShiftRows, SubBytes.

### RSA
Chiffrement asymétrique basé sur la difficulté de factorisation. Clé publique (e, n), clé privée (d, n).

### ElGamal
Chiffrement asymétrique basé sur le logarithme discret. Chiffrement probabiliste.

### EC-ElGamal
Version sur courbe elliptique (secp256k1 — la courbe de Bitcoin). Multiplication scalaire et addition de points.

---

## Dépannage

### Erreur : Port 5000 déjà utilisé

Sur Windows (PowerShell) :
netstat -ano | findstr :5000
taskkill /PID <PID> /F

Sur Linux/Mac :
lsof -i :5000
kill -9 <PID>

### Erreur : Module flask not found

pip install flask

### Erreur : Permission denied pour la base de données

chmod 666 cryptoapp.db

Ou supprimer la base pour qu'elle soit recréée :
rm cryptoapp.db
python app.py

### Le dashboard ne s'affiche pas correctement

- Vérifiez votre connexion internet (Bootstrap CDN)
- Videz le cache du navigateur (Ctrl+Shift+Suppr)
- Testez avec un autre navigateur

---

## Équipe

| Nom | Rôle |
|-----|------|
| Équipe pédagogique | Développement des algorithmes |
| Pr. Asmae EL KASSIRI | Encadrement académique |

Établissement : École Mohammadia d'Ingénieurs (EMI) — Département Génie Informatique

Cours : Cryptographie et Sécurité des Systèmes d'Information

Année académique : 2025 — 2026

---

## Licence

Ce projet est développé dans un cadre pédagogique à l'École Mohammadia d'Ingénieurs. Toute reproduction ou utilisation doit mentionner la source.

Particularité majeure : Aucune bibliothèque cryptographique externe n'a été utilisée. Tous les algorithmes sont implémentés à partir des mathématiques fondamentales (arithmétique modulaire, GF(2^8), etc.).

---

CryptoApp — Comprendre la cryptographie par la pratique. 🔐
