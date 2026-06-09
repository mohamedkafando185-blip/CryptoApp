# =============================================================================
# crypto_algorithms.py
# Implémentation PURE de tous les algorithmes de cryptographie
# Projet académique - Cours de Pr. Asmae EL KASSIRI
# IMPORTANT : Aucune bibliothèque cryptographique externe n'est utilisée.
#             Tout est implémenté à partir des mathématiques fondamentales.
# =============================================================================

import random
import math
import struct
import hashlib


# =============================================================================
# PARTIE 1: CHIFFREMENTS SYMÉTRIQUES CLASSIQUES
# =============================================================================

# -----------------------------------------------------------------------------
# 1. CODE CÉSAR (CAESAR CIPHER)
# -----------------------------------------------------------------------------
def cesar_chiffrer(texte: str, decalage: int) -> str:
    """
    Chiffre un texte avec le code César.
    Principe: Chaque lettre est décalée d'un nombre fixe de positions dans l'alphabet.
    Les chiffres (0-9) sont également décalés circulairement.
    Formule: C = (M + k) mod 26 pour les lettres, (M + k) mod 10 pour les chiffres.
    """
    resultat = []
    decalage_lettres = decalage % 26
    decalage_chiffres = decalage % 10
    
    for c in texte:
        if c.isalpha():
            # Traitement des lettres
            base = ord('A') if c.isupper() else ord('a')
            nouvelle_pos = (ord(c) - base + decalage_lettres) % 26
            resultat.append(chr(base + nouvelle_pos))
        elif c.isdigit():
            # Traitement des chiffres (0-9)
            chiffre = int(c)
            nouveau_chiffre = (chiffre + decalage_chiffres) % 10
            resultat.append(str(nouveau_chiffre))
        else:
            # Conserver les autres caractères
            resultat.append(c)
    return ''.join(resultat)


def cesar_dechiffrer(texte: str, decalage: int) -> str:
    """
    Déchiffre un texte chiffré avec le code César.
    Pour déchiffrer, on soustrait le décalage.
    """
    resultat = []
    decalage_lettres = decalage % 26
    decalage_chiffres = decalage % 10
    
    for c in texte:
        if c.isalpha():
            # Traitement des lettres
            base = ord('A') if c.isupper() else ord('a')
            nouvelle_pos = (ord(c) - base - decalage_lettres) % 26
            resultat.append(chr(base + nouvelle_pos))
        elif c.isdigit():
            # Traitement des chiffres (0-9) - on soustrait le décalage
            chiffre = int(c)
            nouveau_chiffre = (chiffre - decalage_chiffres) % 10
            resultat.append(str(nouveau_chiffre))
        else:
            # Conserver les autres caractères
            resultat.append(c)
    return ''.join(resultat)


# -----------------------------------------------------------------------------
# 2. CHIFFREMENT DE VIGENÈRE
# -----------------------------------------------------------------------------
def vigenere_chiffrer(texte: str, cle: str) -> str:
    """
    Chiffre un texte avec Vigenère.
    Principe: Chaque lettre est décalée d'une valeur dépendant de la lettre de la clé.
    Formule: C_i = (M_i + K_{i mod |K|}) mod 26
    """
    if not cle or not cle.isalpha():
        raise ValueError("La clé doit contenir uniquement des lettres")
    
    resultat = []
    cle_maj = cle.upper()
    idx_cle = 0
    
    for c in texte:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decalage = ord(cle_maj[idx_cle % len(cle_maj)]) - ord('A')
            nouvelle_pos = (ord(c) - base + decalage) % 26
            resultat.append(chr(base + nouvelle_pos))
            idx_cle += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


def vigenere_dechiffrer(texte: str, cle: str) -> str:
    """
    Déchiffre un texte chiffré avec Vigenère.
    Formule: M_i = (C_i - K_{i mod |K|} + 26) mod 26
    """
    if not cle or not cle.isalpha():
        raise ValueError("La clé doit contenir uniquement des lettres")
    
    resultat = []
    cle_maj = cle.upper()
    idx_cle = 0
    
    for c in texte:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decalage = ord(cle_maj[idx_cle % len(cle_maj)]) - ord('A')
            nouvelle_pos = (ord(c) - base - decalage + 26) % 26
            resultat.append(chr(base + nouvelle_pos))
            idx_cle += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


# -----------------------------------------------------------------------------
# 3. VERNAM (MASQUE JETABLE / ONE-TIME PAD)
# -----------------------------------------------------------------------------
def vernam_chiffrer(texte: str, cle: str) -> tuple:
    """
    Chiffre un texte avec le masque jetable (XOR).
    Principe: Chaque octet du message est XORé avec un octet de la clé.
    Sécurité parfaite SI la clé est aléatoire, aussi longue que le message, et non réutilisée.
    """
    # Conversion en bytes
    msg_bytes = texte.encode('utf-8')
    cle_bytes = cle.encode('utf-8')
    
    # Si la clé est plus courte, on la répète (ATTENTION: cela réduit la sécurité!)
    if len(cle_bytes) < len(msg_bytes):
        repetitions = (len(msg_bytes) // len(cle_bytes)) + 1
        cle_bytes = (cle_bytes * repetitions)[:len(msg_bytes)]
    elif len(cle_bytes) > len(msg_bytes):
        cle_bytes = cle_bytes[:len(msg_bytes)]
    
    # XOR octet par octet
    chiffre_bytes = bytes([m ^ c for m, c in zip(msg_bytes, cle_bytes)])
    
    return chiffre_bytes.hex(), cle_bytes.hex()


def vernam_dechiffrer(chiffre_hex: str, cle_hex: str) -> str:
    """
    Déchiffre un texte chiffré avec Vernam.
    Le XOR est involutif: (M XOR K) XOR K = M
    """
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    cle_bytes = bytes.fromhex(cle_hex)
    
    if len(cle_bytes) < len(chiffre_bytes):
        repetitions = (len(chiffre_bytes) // len(cle_bytes)) + 1
        cle_bytes = (cle_bytes * repetitions)[:len(chiffre_bytes)]
    
    msg_bytes = bytes([c ^ k for c, k in zip(chiffre_bytes, cle_bytes)])
    return msg_bytes.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 4. RC4 (RIVEST CIPHER 4)
# -----------------------------------------------------------------------------
def rc4_ksa(cle: bytes) -> list:
    """
    Key Scheduling Algorithm - Initialise le tableau S de 256 octets.
    """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + cle[i % len(cle)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list, longueur: int) -> list:
    """
    Pseudo-Random Generation Algorithm - Génère le flux de clés.
    """
    flux = []
    i = j = 0
    S = S.copy()
    for _ in range(longueur):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        flux.append(S[(S[i] + S[j]) % 256])
    return flux


def rc4_chiffrer(texte: str, cle: str) -> str:
    """
    Chiffre/Déchiffre un texte avec RC4 (symétrique).
    """
    cle_bytes = cle.encode('utf-8')
    msg_bytes = texte.encode('utf-8')
    
    S = rc4_ksa(cle_bytes)
    flux = rc4_prga(S, len(msg_bytes))
    
    resultat_bytes = bytes([m ^ f for m, f in zip(msg_bytes, flux)])
    return resultat_bytes.hex()


def rc4_dechiffrer(chiffre_hex: str, cle: str) -> str:
    """
    Déchiffre un texte RC4 (identique au chiffrement).
    """
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    cle_bytes = cle.encode('utf-8')
    
    S = rc4_ksa(cle_bytes)
    flux = rc4_prga(S, len(chiffre_bytes))
    
    msg_bytes = bytes([c ^ f for c, f in zip(chiffre_bytes, flux)])
    return msg_bytes.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 5. DES (DATA ENCRYPTION STANDARD) - Tables et implémentation complète
# -----------------------------------------------------------------------------

# Tables de permutation DES
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes
SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]


def des_permuter(bits: list, table: list) -> list:
    """Applique une permutation à une liste de bits."""
    return [bits[i-1] for i in table]


def des_rotation_gauche(bits: list, n: int) -> list:
    """Effectue une rotation circulaire à gauche."""
    return bits[n:] + bits[:n]


def des_str_to_bits(s: str, longueur: int) -> list:
    """Convertit une chaîne en liste de bits (longueur = nombre d'octets)."""
    bits = []
    for c in s[:longueur]:
        bits.extend([int(b) for b in format(ord(c), '08b')])
    # Padding avec des zéros si nécessaire
    while len(bits) < longueur * 8:
        bits.append(0)
    return bits


def des_bits_to_bytes(bits: list) -> bytes:
    """Convertit une liste de bits en bytes."""
    resultat = bytearray()
    for i in range(0, len(bits), 8):
        if i + 8 > len(bits):
            break
        octet = 0
        for j in range(8):
            octet = (octet << 1) | bits[i + j]
        resultat.append(octet)
    return bytes(resultat)


def des_generer_sous_cles(cle_64: list) -> list:
    """Génère les 16 sous-clés de 48 bits à partir de la clé de 64 bits."""
    # Application de PC1 pour obtenir 56 bits
    cle_56 = des_permuter(cle_64, PC1)
    
    # Division en deux moitiés de 28 bits
    C = cle_56[:28]
    D = cle_56[28:]
    
    sous_cles = []
    for i in range(16):
        # Rotation
        C = des_rotation_gauche(C, SHIFTS[i])
        D = des_rotation_gauche(D, SHIFTS[i])
        # Application de PC2 pour obtenir 48 bits
        sous_cle = des_permuter(C + D, PC2)
        sous_cles.append(sous_cle)
    
    return sous_cles


def des_fonction_f(R: list, sous_cle: list) -> list:
    """Fonction F de DES."""
    # Expansion de 32 à 48 bits
    R_exp = des_permuter(R, E)
    
    # XOR avec la sous-clé
    xor = [R_exp[i] ^ sous_cle[i] for i in range(48)]
    
    # Application des S-Boxes (48 -> 32 bits)
    sortie = []
    for i in range(8):
        groupe = xor[i*6:(i+1)*6]
        ligne = (groupe[0] << 1) | groupe[5]
        colonne = (groupe[1] << 3) | (groupe[2] << 2) | (groupe[3] << 1) | groupe[4]
        valeur = SBOX[i][ligne][colonne]
        sortie.extend([int(b) for b in format(valeur, '04b')])
    
    # Permutation P
    return des_permuter(sortie, P)


def des_chiffrer_bloc(bloc_64: list, sous_cles: list) -> list:
    """
    Chiffre un bloc de 64 bits avec DES.
    Les sous-clés sont utilisées dans l'ordre normal.
    """
    # Permutation initiale
    bloc = des_permuter(bloc_64, IP)
    
    L = bloc[:32]
    R = bloc[32:]
    
    # 16 rondes de Feistel
    for i in range(16):
        L_suivant = R
        F = des_fonction_f(R, sous_cles[i])
        R_suivant = [L[j] ^ F[j] for j in range(32)]
        L, R = L_suivant, R_suivant
    
    # Échange final (L et R sont échangés avant la permutation finale)
    bloc_final = R + L
    return des_permuter(bloc_final, IP_INV)


def des_dechiffrer_bloc(bloc_64: list, sous_cles: list) -> list:
    """
    Déchiffre un bloc de 64 bits avec DES.
    Les sous-clés sont utilisées dans l'ordre INVERSE.
    """
    # Même structure que le chiffrement, mais avec les sous-clés en ordre inverse
    # Permutation initiale
    bloc = des_permuter(bloc_64, IP)
    
    L = bloc[:32]
    R = bloc[32:]
    
    # 16 rondes de Feistel avec sous-clés inversées
    for i in range(16):
        L_suivant = R
        F = des_fonction_f(R, sous_cles[15 - i])  # Ordre inverse !
        R_suivant = [L[j] ^ F[j] for j in range(32)]
        L, R = L_suivant, R_suivant
    
    # Échange final
    bloc_final = R + L
    return des_permuter(bloc_final, IP_INV)


# -----------------------------------------------------------------------------
# 5.1 DES - Mode ECB (Electronic Codebook)
# -----------------------------------------------------------------------------

def des_chiffrer(texte: str, cle: str) -> str:
    """
    Chiffre un texte avec DES en mode ECB.
    Retourne le résultat en hexadécimal.
    """
    # Préparation de la clé (64 bits = 8 octets)
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    # Padding PKCS#7
    texte_bytes = texte.encode('utf-8')
    padding = 8 - (len(texte_bytes) % 8)
    if padding == 0:
        padding = 8
    texte_bytes += bytes([padding] * padding)
    
    resultat = bytearray()
    for i in range(0, len(texte_bytes), 8):
        bloc = texte_bytes[i:i+8]
        
        # Conversion du bloc en bits
        bloc_bits = []
        for octet in bloc:
            bloc_bits.extend([int(b) for b in format(octet, '08b')])
        
        # Chiffrement
        bloc_chiffre_bits = des_chiffrer_bloc(bloc_bits, sous_cles)
        
        # Conversion en octets
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | bloc_chiffre_bits[j + k]
            resultat.append(octet)
    
    return resultat.hex()


def des_dechiffrer(chiffre_hex: str, cle: str) -> str:
    """
    Déchiffre un texte DES en mode ECB.
    Reçoit le texte chiffré en hexadécimal.
    """
    # Préparation de la clé
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    resultat = bytearray()
    
    for i in range(0, len(chiffre_bytes), 8):
        bloc = chiffre_bytes[i:i+8]
        
        # Conversion en bits
        bloc_bits = []
        for octet in bloc:
            bloc_bits.extend([int(b) for b in format(octet, '08b')])
        
        # Déchiffrement (les sous-clés sont automatiquement inversées dans la fonction)
        bloc_dechiffre_bits = des_dechiffrer_bloc(bloc_bits, sous_cles)
        
        # Conversion en octets
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | bloc_dechiffre_bits[j + k]
            resultat.append(octet)
    
    # Suppression du padding PKCS#7
    if len(resultat) > 0:
        padding = resultat[-1]
        if 1 <= padding <= 8:
            resultat = resultat[:-padding]
    
    return resultat.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 6. MODES CBC ET CFB
# -----------------------------------------------------------------------------

def cbc_chiffrer(texte: str, cle: str, iv_hex: str = None) -> dict:
    """
    Chiffre un texte avec DES en mode CBC.
    Formule: C_i = E(P_i XOR C_{i-1}), avec C_0 = IV
    Retourne: {'chiffre': hex, 'iv': hex}
    """
    import random
    
    # Génération d'un IV aléatoire si non fourni
    if iv_hex is None or iv_hex == "":
        iv = bytes([random.randint(0, 255) for _ in range(8)])
        iv_hex = iv.hex()
    else:
        iv = bytes.fromhex(iv_hex)
    
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    # Padding PKCS#7
    texte_bytes = texte.encode('utf-8')
    padding = 8 - (len(texte_bytes) % 8)
    if padding == 0:
        padding = 8
    texte_bytes += bytes([padding] * padding)
    
    resultat = bytearray()
    bloc_precedent = list(iv)  # IV en liste d'octets
    
    for i in range(0, len(texte_bytes), 8):
        bloc_clair = texte_bytes[i:i+8]
        
        # XOR avec le bloc précédent (ou IV pour le premier bloc)
        bloc_xor = bytearray()
        for j in range(8):
            bloc_xor.append(bloc_clair[j] ^ bloc_precedent[j])
        
        # Conversion en bits
        bloc_bits = []
        for octet in bloc_xor:
            for b in format(octet, '08b'):
                bloc_bits.append(int(b))
        
        # Chiffrement
        bloc_chiffre_bits = des_chiffrer_bloc(bloc_bits, sous_cles)
        
        # Conversion en octets
        bloc_chiffre = bytearray()
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | bloc_chiffre_bits[j + k]
            bloc_chiffre.append(octet)
        
        resultat.extend(bloc_chiffre)
        bloc_precedent = list(bloc_chiffre)
    
    return {'chiffre': resultat.hex(), 'iv': iv_hex}


def cbc_dechiffrer(chiffre_hex: str, cle: str, iv_hex: str) -> str:
    """
    Déchiffre un texte DES-CBC.
    Formule: P_i = D(C_i) XOR C_{i-1}
    """
    if not chiffre_hex or not cle or not iv_hex:
        return ""
    
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    iv = bytes.fromhex(iv_hex)
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    resultat = bytearray()
    bloc_precedent = list(iv)
    
    for i in range(0, len(chiffre_bytes), 8):
        bloc_chiffre = chiffre_bytes[i:i+8]
        
        # Conversion en bits
        bloc_bits = []
        for octet in bloc_chiffre:
            for b in format(octet, '08b'):
                bloc_bits.append(int(b))
        
        # Déchiffrement
        bloc_dechiffre_bits = des_dechiffrer_bloc(bloc_bits, sous_cles)
        
        # Conversion en octets
        bloc_dechiffre = bytearray()
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | bloc_dechiffre_bits[j + k]
            bloc_dechiffre.append(octet)
        
        # XOR avec le bloc précédent
        for j in range(8):
            resultat.append(bloc_dechiffre[j] ^ bloc_precedent[j])
        
        bloc_precedent = list(bloc_chiffre)
    
    # Suppression du padding PKCS#7
    if len(resultat) > 0:
        padding = resultat[-1]
        if 1 <= padding <= 8:
            # Vérifier que le padding est valide
            valide = True
            for i in range(1, padding + 1):
                if resultat[-i] != padding:
                    valide = False
                    break
            if valide:
                resultat = resultat[:-padding]
    
    return resultat.decode('utf-8', errors='replace')


def cfb_chiffrer(texte: str, cle: str, iv_hex: str = None) -> dict:
    """
    Chiffre un texte avec DES en mode CFB (Cipher Feedback).
    Formule: C_i = P_i XOR E(C_{i-1}), avec C_0 = IV
    Retourne: {'chiffre': hex, 'iv': hex}
    """
    import random
    
    if iv_hex is None or iv_hex == "":
        iv = bytes([random.randint(0, 255) for _ in range(8)])
        iv_hex = iv.hex()
    else:
        iv = bytes.fromhex(iv_hex)
    
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    texte_bytes = texte.encode('utf-8')
    resultat = bytearray()
    registre = list(iv)
    
    for i in range(0, len(texte_bytes), 8):
        bloc_clair = texte_bytes[i:i+8]
        
        # Chiffrement du registre
        registre_bits = []
        for octet in registre:
            for b in format(octet, '08b'):
                registre_bits.append(int(b))
        
        sortie_bits = des_chiffrer_bloc(registre_bits, sous_cles)
        
        # Conversion de la sortie en octets
        sortie_bytes = bytearray()
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | sortie_bits[j + k]
            sortie_bytes.append(octet)
        
        # XOR avec le texte clair
        bloc_chiffre = bytearray()
        for j in range(len(bloc_clair)):
            bloc_chiffre.append(bloc_clair[j] ^ sortie_bytes[j])
        
        resultat.extend(bloc_chiffre)
        
        # Mise à jour du registre (shift)
        nouveau_registre = list(registre[len(bloc_clair):])
        nouveau_registre.extend(bloc_chiffre)
        registre = nouveau_registre[:8]
    
    return {'chiffre': resultat.hex(), 'iv': iv_hex}


def cfb_dechiffrer(chiffre_hex: str, cle: str, iv_hex: str) -> str:
    """
    Déchiffre un texte DES-CFB.
    Formule: P_i = C_i XOR E(C_{i-1})
    """
    if not chiffre_hex or not cle or not iv_hex:
        return ""
    
    cle_bits = des_str_to_bits(cle, 8)
    sous_cles = des_generer_sous_cles(cle_bits)
    
    iv = bytes.fromhex(iv_hex)
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    resultat = bytearray()
    registre = list(iv)
    
    for i in range(0, len(chiffre_bytes), 8):
        bloc_chiffre = chiffre_bytes[i:i+8]
        
        # Chiffrement du registre (même qu'au chiffrement !)
        registre_bits = []
        for octet in registre:
            for b in format(octet, '08b'):
                registre_bits.append(int(b))
        
        sortie_bits = des_chiffrer_bloc(registre_bits, sous_cles)
        
        # Conversion de la sortie en octets
        sortie_bytes = bytearray()
        for j in range(0, 64, 8):
            octet = 0
            for k in range(8):
                octet = (octet << 1) | sortie_bits[j + k]
            sortie_bytes.append(octet)
        
        # XOR pour obtenir le clair
        bloc_clair = bytearray()
        for j in range(len(bloc_chiffre)):
            bloc_clair.append(bloc_chiffre[j] ^ sortie_bytes[j])
        
        resultat.extend(bloc_clair)
        
        # Mise à jour du registre (shift)
        nouveau_registre = list(registre[len(bloc_chiffre):])
        nouveau_registre.extend(bloc_chiffre)
        registre = nouveau_registre[:8]
    
    return resultat.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 7. AES-128 (ADVANCED ENCRYPTION STANDARD)
# -----------------------------------------------------------------------------

# S-Box AES (substitution non-linéaire)
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# S-Box inverse pour déchiffrement
AES_SBOX_INV = [0] * 256
for i, v in enumerate(AES_SBOX):
    AES_SBOX_INV[v] = i

# Constantes de ronde Rcon
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def aes_xtime(x):
    """Multiplication par 2 dans GF(2^8) pour MixColumns."""
    return ((x << 1) ^ 0x1b) & 0xff if (x & 0x80) else (x << 1) & 0xff


def aes_gmul(a, b):
    """Multiplication dans GF(2^8) pour MixColumns."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = aes_xtime(a)
        b >>= 1
    return result


def aes_sub_bytes(etat):
    """SubBytes: application de la S-Box à chaque octet."""
    return [AES_SBOX[b] for b in etat]


def aes_sub_bytes_inv(etat):
    """InvSubBytes: application de la S-Box inverse."""
    return [AES_SBOX_INV[b] for b in etat]


def aes_shift_rows(etat):
    """
    ShiftRows: décalage cyclique des lignes.
    Ligne 0: pas de décalage
    Ligne 1: décalage de 1
    Ligne 2: décalage de 2
    Ligne 3: décalage de 3
    """
    return [
        etat[0],  etat[5],  etat[10], etat[15],
        etat[4],  etat[9],  etat[14], etat[3],
        etat[8],  etat[13], etat[2],  etat[7],
        etat[12], etat[1],  etat[6],  etat[11]
    ]


def aes_shift_rows_inv(etat):
    """InvShiftRows: décalage inverse."""
    return [
        etat[0],  etat[13], etat[10], etat[7],
        etat[4],  etat[1],  etat[14], etat[11],
        etat[8],  etat[5],  etat[2],  etat[15],
        etat[12], etat[9],  etat[6],  etat[3]
    ]


def aes_mix_columns(etat):
    """
    MixColumns: multiplication des colonnes par la matrice MDS.
    Chaque colonne est traitée comme un polynôme sur GF(2^8).
    """
    result = [0] * 16
    for col in range(4):
        s0, s1, s2, s3 = etat[col*4], etat[col*4+1], etat[col*4+2], etat[col*4+3]
        result[col*4]   = aes_gmul(s0, 2) ^ aes_gmul(s1, 3) ^ s2 ^ s3
        result[col*4+1] = s0 ^ aes_gmul(s1, 2) ^ aes_gmul(s2, 3) ^ s3
        result[col*4+2] = s0 ^ s1 ^ aes_gmul(s2, 2) ^ aes_gmul(s3, 3)
        result[col*4+3] = aes_gmul(s0, 3) ^ s1 ^ s2 ^ aes_gmul(s3, 2)
    return result


def aes_mix_columns_inv(etat):
    """InvMixColumns: multiplication par la matrice inverse."""
    result = [0] * 16
    for col in range(4):
        s0, s1, s2, s3 = etat[col*4], etat[col*4+1], etat[col*4+2], etat[col*4+3]
        result[col*4]   = aes_gmul(s0, 14) ^ aes_gmul(s1, 11) ^ aes_gmul(s2, 13) ^ aes_gmul(s3, 9)
        result[col*4+1] = aes_gmul(s0, 9)  ^ aes_gmul(s1, 14) ^ aes_gmul(s2, 11) ^ aes_gmul(s3, 13)
        result[col*4+2] = aes_gmul(s0, 13) ^ aes_gmul(s1, 9)  ^ aes_gmul(s2, 14) ^ aes_gmul(s3, 11)
        result[col*4+3] = aes_gmul(s0, 11) ^ aes_gmul(s1, 13) ^ aes_gmul(s2, 9)  ^ aes_gmul(s3, 14)
    return result


def aes_add_round_key(etat, round_key):
    """AddRoundKey: XOR de l'état avec la sous-clé de la ronde."""
    return [etat[i] ^ round_key[i] for i in range(16)]


def aes_key_expansion(cle_initiale):
    """
    Expansion de clé AES-128.
    Génère 11 sous-clés de 16 octets à partir de la clé initiale de 128 bits.
    """
    # La clé initiale est en mots de 4 octets
    mots = [cle_initiale[i*4:(i+1)*4] for i in range(4)]
    
    for i in range(4, 44):
        temp = mots[i-1][:]
        if i % 4 == 0:
            # RotWord: rotation circulaire du mot
            temp = temp[1:] + temp[:1]
            # SubWord: application de la S-Box
            temp = [AES_SBOX[b] for b in temp]
            # XOR avec la constante de ronde
            temp[0] ^= Rcon[(i//4)-1]
        # Nouveau mot = mot[i-4] XOR temp
        nouveau_mot = [mots[i-4][j] ^ temp[j] for j in range(4)]
        mots.append(nouveau_mot)
    
    # Regrouper en sous-clés de 16 octets
    round_keys = []
    for i in range(11):
        round_key = []
        for j in range(4):
            round_key.extend(mots[i*4 + j])
        round_keys.append(round_key)
    
    return round_keys


def aes_chiffrer_bloc(bloc_16, round_keys):
    """Chiffre un bloc de 16 octets avec AES-128."""
    # Ronde initiale: AddRoundKey
    etat = aes_add_round_key(bloc_16, round_keys[0])
    
    # 9 rondes complètes
    for ronde in range(1, 10):
        etat = aes_sub_bytes(etat)
        etat = aes_shift_rows(etat)
        etat = aes_mix_columns(etat)
        etat = aes_add_round_key(etat, round_keys[ronde])
    
    # Ronde finale: pas de MixColumns
    etat = aes_sub_bytes(etat)
    etat = aes_shift_rows(etat)
    etat = aes_add_round_key(etat, round_keys[10])
    
    return etat


def aes_dechiffrer_bloc(bloc_16, round_keys):
    """Déchiffre un bloc de 16 octets avec AES-128."""
    # Ronde initiale inverse
    etat = aes_add_round_key(bloc_16, round_keys[10])
    
    for ronde in range(9, 0, -1):
        etat = aes_shift_rows_inv(etat)
        etat = aes_sub_bytes_inv(etat)
        etat = aes_add_round_key(etat, round_keys[ronde])
        etat = aes_mix_columns_inv(etat)
    
    # Ronde finale inverse
    etat = aes_shift_rows_inv(etat)
    etat = aes_sub_bytes_inv(etat)
    etat = aes_add_round_key(etat, round_keys[0])
    
    return etat


def aes_chiffrer(texte: str, cle: str) -> str:
    """Chiffre un texte avec AES-128 en mode ECB."""
    # Préparation de la clé (16 octets)
    cle_bytes = cle.encode('utf-8')[:16]
    if len(cle_bytes) < 16:
        cle_bytes = cle_bytes + b'\x00' * (16 - len(cle_bytes))
    
    round_keys = aes_key_expansion(list(cle_bytes))
    
    # Padding PKCS#7
    texte_bytes = texte.encode('utf-8')
    padding = 16 - (len(texte_bytes) % 16)
    texte_bytes += bytes([padding] * padding)
    
    resultat = bytearray()
    for i in range(0, len(texte_bytes), 16):
        bloc = list(texte_bytes[i:i+16])
        bloc_chiffre = aes_chiffrer_bloc(bloc, round_keys)
        resultat.extend(bloc_chiffre)
    
    return resultat.hex()


def aes_dechiffrer(chiffre_hex: str, cle: str) -> str:
    """Déchiffre un texte AES-128."""
    cle_bytes = cle.encode('utf-8')[:16]
    if len(cle_bytes) < 16:
        cle_bytes = cle_bytes + b'\x00' * (16 - len(cle_bytes))
    
    round_keys = aes_key_expansion(list(cle_bytes))
    
    chiffre_bytes = bytes.fromhex(chiffre_hex)
    resultat = bytearray()
    
    for i in range(0, len(chiffre_bytes), 16):
        bloc = list(chiffre_bytes[i:i+16])
        bloc_dechiffre = aes_dechiffrer_bloc(bloc, round_keys)
        resultat.extend(bloc_dechiffre)
    
    # Suppression du padding
    padding = resultat[-1]
    if 1 <= padding <= 16:
        resultat = resultat[:-padding]
    
    return resultat.decode('utf-8', errors='replace')


# =============================================================================
# PARTIE 2: CHIFFREMENTS ASYMÉTRIQUES
# =============================================================================

# -----------------------------------------------------------------------------
# 8. RSA (RIVEST-SHAMIR-ADLEMAN)
# -----------------------------------------------------------------------------

def rsa_est_premier_miller_rabin(n: int, iterations: int = 40) -> bool:
    """
    Test de primalité de Miller-Rabin probabiliste.
    Déterministe pour n < 2^64 avec des témoins bien choisis.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    
    # Écrire n-1 = d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    
    def test_temoin(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False
    
    # Témoins pour la plage 64 bits
    temoins = [2, 3, 5, 7, 11, 13, 17]
    for a in temoins:
        if a >= n:
            continue
        if not test_temoin(a):
            return False
    return True


def rsa_generer_premier(bits: int) -> int:
    """Génère un nombre premier aléatoire de 'bits' bits."""
    while True:
        n = random.getrandbits(bits)
        # S'assurer que le nombre est impair et a le bon nombre de bits
        n |= (1 << (bits - 1)) | 1
        if rsa_est_premier_miller_rabin(n):
            return n


def rsa_pgcd(a: int, b: int) -> int:
    """Algorithme d'Euclide pour le PGCD."""
    while b:
        a, b = b, a % b
    return a


def rsa_inverse_modulaire(e: int, phi: int) -> int:
    """Calcule l'inverse modulaire d par l'algorithme d'Euclide étendu."""
    # Algorithme d'Euclide étendu: trouve d tel que e*d ≡ 1 (mod phi)
    ancien_r, r = e, phi
    ancien_s, s = 1, 0
    
    while r != 0:
        quotient = ancien_r // r
        ancien_r, r = r, ancien_r - quotient * r
        ancien_s, s = s, ancien_s - quotient * s
    
    # ancien_r contient le PGCD (doit être 1)
    if ancien_r != 1:
        raise ValueError("e et phi(n) ne sont pas premiers entre eux")
    
    return ancien_s % phi


def rsa_generer_cles(bits: int = 512) -> dict:
    """
    Génère une paire de clés RSA.
    bits: taille totale de n en bits (p et q font chacun bits/2 bits)
    """
    taille = bits // 2
    p = rsa_generer_premier(taille)
    q = rsa_generer_premier(taille)
    while q == p:
        q = rsa_generer_premier(taille)
    
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Exposant public (Fermat F4 = 65537)
    e = 65537
    if rsa_pgcd(e, phi_n) != 1:
        # Si 65537 n'est pas valide, on cherche un autre e
        e = 3
        while rsa_pgcd(e, phi_n) != 1:
            e += 2
    
    d = rsa_inverse_modulaire(e, phi_n)
    
    return {
        'cle_publique': {'e': e, 'n': n},
        'cle_privee': {'d': d, 'n': n},
        'p': p, 'q': q,
        'phi_n': phi_n
    }


def rsa_chiffrer(message: str, e: int, n: int) -> str:
    """
    Chiffre un message avec RSA.
    Chaque caractère est chiffré séparément.
    """
    msg_bytes = message.encode('utf-8')
    chiffres = []
    for octet in msg_bytes:
        if octet >= n:
            raise ValueError(f"L'octet {octet} est >= n. Utilisez un module n plus grand.")
        c = pow(octet, e, n)
        chiffres.append(str(c))
    return ','.join(chiffres)


def rsa_dechiffrer(chiffre_str: str, d: int, n: int) -> str:
    """Déchiffre un message chiffré par RSA."""
    chiffres = [int(x.strip()) for x in chiffre_str.split(',')]
    msg_bytes = bytes([pow(c, d, n) for c in chiffres])
    return msg_bytes.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 9. ELGAMAL
# -----------------------------------------------------------------------------

def elgamal_generer_premier_sur(bits: int) -> tuple:
    """
    Génère un nombre premier sûr p = 2*q + 1 où q est aussi premier.
    Retourne (p, q).
    """
    while True:
        q = rsa_generer_premier(bits - 1)
        p = 2 * q + 1
        if rsa_est_premier_miller_rabin(p):
            return p, q


def elgamal_trouver_generateur(p: int) -> int:
    """
    Trouve un générateur du groupe cyclique Z_p*.
    """
    # Factorisation simplifiée de p-1
    facteurs = []
    temp = p - 1
    for i in range(2, 100):
        if temp % i == 0:
            facteurs.append(i)
            while temp % i == 0:
                temp //= i
    if temp > 1:
        facteurs.append(temp)
    
    for g in range(2, p):
        ok = True
        for q in facteurs:
            if pow(g, (p-1)//q, p) == 1:
                ok = False
                break
        if ok:
            return g
    return 2


def elgamal_generer_cles(bits: int = 256) -> dict:
    """Génère une paire de clés ElGamal."""
    p, q = elgamal_generer_premier_sur(bits)
    g = elgamal_trouver_generateur(p)
    
    # Clé privée x
    x = random.randint(2, p - 2)
    
    # Clé publique y = g^x mod p
    y = pow(g, x, p)
    
    return {
        'cle_publique': {'p': p, 'g': g, 'y': y},
        'cle_privee': {'x': x}
    }


def elgamal_chiffrer(message: str, p: int, g: int, y: int) -> str:
    """Chiffre un message avec ElGamal."""
    msg_bytes = message.encode('utf-8')
    resultat = []
    
    for octet in msg_bytes:
        # k doit être aléatoire pour chaque octet (chiffrement probabiliste)
        k = random.randint(2, p - 2)
        a = pow(g, k, p)
        b = (octet * pow(y, k, p)) % p
        resultat.append(f"{a}:{b}")
    
    return ','.join(resultat)


def elgamal_dechiffrer(chiffre_str: str, x: int, p: int) -> str:
    """Déchiffre un message ElGamal."""
    paires = chiffre_str.split(',')
    msg_bytes = bytearray()
    
    for paire in paires:
        a_str, b_str = paire.split(':')
        a = int(a_str)
        b = int(b_str)
        
        # s = a^x mod p
        s = pow(a, x, p)
        # Inverse de s par Fermat: s^(p-2) mod p
        s_inv = pow(s, p - 2, p)
        m = (b * s_inv) % p
        msg_bytes.append(m)
    
    return msg_bytes.decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# 10. EC-ELGAMAL (ELGAMAL SUR COURBE ELLIPTIQUE)
# -----------------------------------------------------------------------------

# Paramètres de la courbe secp256k1 (celle utilisée par Bitcoin)
EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
EC_A = 0
EC_B = 7
EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def ec_inverse_modulaire(a: int, p: int) -> int:
    """Inverse modulaire par le théorème de Fermat."""
    return pow(a, p - 2, p)


def ec_addition_points(P: tuple, Q: tuple, p: int, a: int) -> tuple:
    """Addition de deux points sur la courbe elliptique."""
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 == y2:
        # Doublement du point
        numerateur = (3 * x1 * x1 + a) % p
        denominateur = (2 * y1) % p
        if denominateur == 0:
            return None
        m = (numerateur * ec_inverse_modulaire(denominateur, p)) % p
    else:
        # Addition standard
        if x1 == x2:
            return None
        numerateur = (y2 - y1) % p
        denominateur = (x2 - x1) % p
        m = (numerateur * ec_inverse_modulaire(denominateur, p)) % p
    
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    
    return (x3, y3)


def ec_multiplication_scalaire(k: int, P: tuple, p: int, a: int) -> tuple:
    """Multiplication scalaire k*P sur la courbe elliptique."""
    if k == 0 or P is None:
        return None
    
    resultat = None
    courant = P
    
    while k > 0:
        if k & 1:
            resultat = ec_addition_points(resultat, courant, p, a)
        courant = ec_addition_points(courant, courant, p, a)
        k >>= 1
    
    return resultat


def ec_elgamal_generer_cles() -> dict:
    """Génère une paire de clés EC-ElGamal sur secp256k1."""
    # Clé privée: entier aléatoire entre 1 et n-1
    k_prive = random.randint(1, EC_N - 1)
    
    # Clé publique: Q = k_prive * G
    Q = ec_multiplication_scalaire(k_prive, (EC_GX, EC_GY), EC_P, EC_A)
    
    return {
        'cle_privee': k_prive,
        'cle_publique': {'Qx': Q[0], 'Qy': Q[1]},
        'courbe': 'secp256k1',
        'G': (EC_GX, EC_GY),
        'n': EC_N
    }


def ec_elgamal_chiffrer(message: str, Qx: int, Qy: int) -> str:
    """Chiffre un message avec EC-ElGamal."""
    msg_bytes = message.encode('utf-8')
    resultat = []
    G = (EC_GX, EC_GY)
    
    for octet in msg_bytes:
        # r aléatoire
        r = random.randint(1, EC_N - 1)
        
        # C1 = r * G
        C1 = ec_multiplication_scalaire(r, G, EC_P, EC_A)
        
        # Masque = r * Q
        Q = (Qx, Qy)
        masque = ec_multiplication_scalaire(r, Q, EC_P, EC_A)
        
        # C2 = (message_point) + masque
        # On encode l'octet comme un point M = (octet+1) * G
        M = ec_multiplication_scalaire(octet + 1, G, EC_P, EC_A)
        C2 = ec_addition_points(M, masque, EC_P, EC_A)
        
        resultat.append(f"{C1[0]}:{C1[1]}:{C2[0]}:{C2[1]}")
    
    return '|'.join(resultat)


def ec_elgamal_dechiffrer(chiffre_str: str, k_prive: int) -> str:
    """Déchiffre un message EC-ElGamal."""
    paires = chiffre_str.split('|')
    msg_bytes = bytearray()
    G = (EC_GX, EC_GY)
    
    for paire in paires:
        parties = paire.split(':')
        C1 = (int(parties[0]), int(parties[1]))
        C2 = (int(parties[2]), int(parties[3]))
        
        # Masque = k_prive * C1
        masque = ec_multiplication_scalaire(k_prive, C1, EC_P, EC_A)
        
        # M = C2 - masque
        if masque is not None:
            # L'opposé d'un point est (x, -y mod p)
            masque_neg = (masque[0], (-masque[1]) % EC_P)
            M = ec_addition_points(C2, masque_neg, EC_P, EC_A)
        else:
            M = C2
        
        # Recherche de l'octet: trouver m tel que (m+1)*G = M
        # Recherche linéaire (acceptable pour 256 valeurs)
        point_test = G
        for m in range(256):
            if point_test == M:
                msg_bytes.append(m)
                break
            point_test = ec_addition_points(point_test, G, EC_P, EC_A)
    
    return msg_bytes.decode('utf-8', errors='replace')