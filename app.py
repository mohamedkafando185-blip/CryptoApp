# =============================================================================
# app.py
# Application Flask principale - Projet Cryptographie
# Cours de Pr. Asmae EL KASSIRI
# =============================================================================

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash
)
import sqlite3
import hashlib
import os
from functools import wraps

# Import de tous nos algorithmes de cryptographie
from crypto_algorithms import (
    cesar_chiffrer, cesar_dechiffrer,
    vigenere_chiffrer, vigenere_dechiffrer,
    vernam_chiffrer, vernam_dechiffrer,
    rc4_chiffrer, rc4_dechiffrer,
    des_chiffrer, des_dechiffrer,
    cbc_chiffrer, cbc_dechiffrer,
    cfb_chiffrer, cfb_dechiffrer,
    aes_chiffrer, aes_dechiffrer,
    rsa_generer_cles, rsa_chiffrer, rsa_dechiffrer,
    elgamal_generer_cles, elgamal_chiffrer, elgamal_dechiffrer,
    ec_elgamal_generer_cles, ec_elgamal_chiffrer, ec_elgamal_dechiffrer
)


# =============================================================================
# INITIALISATION DE L'APPLICATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'crypto_app_secret_key_2024')
DB_PATH = 'cryptoapp.db'


# =============================================================================
# FONCTIONS BASE DE DONNÉES
# =============================================================================

def get_db():
    """Ouvre une connexion à la base de données SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialise la base de données avec la table des utilisateurs."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Création de la table utilisateurs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS utilisateurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Création d'un administrateur par défaut si aucun n'existe
    cursor.execute("SELECT COUNT(*) FROM utilisateurs WHERE role = 'admin'")
    if cursor.fetchone()[0] == 0:
        # Mot de passe: Admin@1234 haché en SHA-256
        mdp_hash = hashlib.sha256('Admin@1234'.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO utilisateurs (username, email, password, role)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@cryptoapp.com', mdp_hash, 'admin'))
        print("[INFO] Administrateur par défaut créé: admin / Admin@1234")
    
    conn.commit()
    conn.close()


# =============================================================================
# FONCTIONS DE SÉCURITÉ
# =============================================================================

def hacher_mot_de_passe(mdp: str) -> str:
    """Hache un mot de passe avec SHA-256."""
    return hashlib.sha256(mdp.encode()).hexdigest()


def verifier_mot_de_passe(mdp_saisi: str, hash_stocke: str) -> bool:
    """Vérifie si le mot de passe correspond au hash stocké."""
    return hacher_mot_de_passe(mdp_saisi) == hash_stocke


def login_requis(f):
    """Décorateur: vérifie que l'utilisateur est connecté."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_requis(f):
    """Décorateur: vérifie que l'utilisateur est administrateur."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Accès réservé aux administrateurs.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# ROUTES D'AUTHENTIFICATION
# =============================================================================

@app.route('/')
def index():
    """Page d'accueil."""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion."""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM utilisateurs WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        
        if user and verifier_mot_de_passe(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['email'] = user['email']
            flash(f'Bienvenue {username}!', 'success')
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription."""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        # Validations
        erreurs = []
        if len(username) < 3:
            erreurs.append("Le nom d'utilisateur doit contenir au moins 3 caractères.")
        if '@' not in email:
            erreurs.append("Email invalide.")
        if len(password) < 6:
            erreurs.append("Le mot de passe doit contenir au moins 6 caractères.")
        if password != confirm:
            erreurs.append("Les mots de passe ne correspondent pas.")
        
        if erreurs:
            for err in erreurs:
                flash(err, 'danger')
            return render_template('register.html')
        
        # Hachage et insertion
        mdp_hash = hacher_mot_de_passe(password)
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO utilisateurs (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, mdp_hash, 'user')
            )
            conn.commit()
            flash('Compte créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Ce nom d\'utilisateur ou cet email existe déjà.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Déconnexion."""
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))


# =============================================================================
# ROUTES PRINCIPALES
# =============================================================================

@app.route('/dashboard')
@login_requis
def dashboard():
    """Dashboard utilisateur."""
    return render_template('dashboard.html',
                          username=session['username'],
                          role=session['role'])


@app.route('/admin')
@admin_requis
def admin_dashboard():
    """Dashboard administrateur."""
    conn = get_db()
    utilisateurs = conn.execute(
        "SELECT id, username, email, role, created_at FROM utilisateurs ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template('admin_dashboard.html',
                          utilisateurs=utilisateurs,
                          username=session['username'])


# =============================================================================
# ROUTES API - OPÉRATIONS CRYPTOGRAPHIQUES
# =============================================================================

@app.route('/api/crypto', methods=['POST'])
@login_requis
def api_crypto():
    """
    Route API unique pour toutes les opérations cryptographiques.
    Reçoit: {algorithme, operation, message, params}
    """
    data = request.get_json()
    if not data:
        return jsonify({'erreur': 'Données JSON invalides'}), 400
    
    algo = data.get('algorithme', '').lower()
    operation = data.get('operation', '')
    message = data.get('message', '')
    params = data.get('params', {})
    
    if not message:
        return jsonify({'erreur': 'Message vide'}), 400
    
    try:
        # Code César
        if algo == 'cesar':
            cle = int(params.get('cle', 3))
            if operation == 'chiffrer':
                resultat = cesar_chiffrer(message, cle)
            else:
                resultat = cesar_dechiffrer(message, cle)
            return jsonify({'resultat': resultat, 'info': f'Clé: {cle}'})
        
        # Vigenère
        elif algo == 'vigenere':
            cle = params.get('cle', 'CLE')
            if operation == 'chiffrer':
                resultat = vigenere_chiffrer(message, cle)
            else:
                resultat = vigenere_dechiffrer(message, cle)
            return jsonify({'resultat': resultat, 'info': f'Clé: {cle}'})
        
        # Vernam
        elif algo == 'vernam':
            if operation == 'chiffrer':
                cle = params.get('cle', '')
                resultat, cle_hex = vernam_chiffrer(message, cle)
                return jsonify({'resultat': resultat, 'cle_hex': cle_hex})
            else:
                cle_hex = params.get('cle_hex', '')
                resultat = vernam_dechiffrer(message, cle_hex)
                return jsonify({'resultat': resultat})
        
        # RC4
        elif algo == 'rc4':
            cle = params.get('cle', 'secret')
            if operation == 'chiffrer':
                resultat = rc4_chiffrer(message, cle)
            else:
                resultat = rc4_dechiffrer(message, cle)
            return jsonify({'resultat': resultat})
        
        # DES
        elif algo == 'des':
            cle = params.get('cle', 'DESkey1!')
            if operation == 'chiffrer':
                resultat = des_chiffrer(message, cle)
            else:
                resultat = des_dechiffrer(message, cle)
            return jsonify({'resultat': resultat})
        
        # DES-CBC
        elif algo == 'cbc':
            cle = params.get('cle', 'DESkey1!')
            if operation == 'chiffrer':
                res = cbc_chiffrer(message, cle)
                return jsonify({'resultat': res['chiffre'], 'iv': res['iv']})
            else:
                iv = params.get('iv', '')
                resultat = cbc_dechiffrer(message, cle, iv)
                return jsonify({'resultat': resultat})
        
        # DES-CFB
        elif algo == 'cfb':
            cle = params.get('cle', 'DESkey1!')
            if operation == 'chiffrer':
                res = cfb_chiffrer(message, cle)
                return jsonify({'resultat': res['chiffre'], 'iv': res['iv']})
            else:
                iv = params.get('iv', '')
                resultat = cfb_dechiffrer(message, cle, iv)
                return jsonify({'resultat': resultat})
        
        # AES
        elif algo == 'aes':
            cle = params.get('cle', 'AESkey_16bytes!')
            if operation == 'chiffrer':
                resultat = aes_chiffrer(message, cle)
            else:
                resultat = aes_dechiffrer(message, cle)
            return jsonify({'resultat': resultat})
        
        # RSA
        elif algo == 'rsa':
            if operation == 'chiffrer':
                e = int(params.get('e', 0))
                n = int(params.get('n', 0))
                resultat = rsa_chiffrer(message, e, n)
            else:
                d = int(params.get('d', 0))
                n = int(params.get('n', 0))
                resultat = rsa_dechiffrer(message, d, n)
            return jsonify({'resultat': resultat})
        
        # ElGamal
        elif algo == 'elgamal':
            if operation == 'chiffrer':
                p = int(params.get('p', 0))
                g = int(params.get('g', 0))
                y = int(params.get('y', 0))
                resultat = elgamal_chiffrer(message, p, g, y)
            else:
                x = int(params.get('x', 0))
                p = int(params.get('p', 0))
                resultat = elgamal_dechiffrer(message, x, p)
            return jsonify({'resultat': resultat})
        
        # EC-ElGamal
        elif algo == 'ec_elgamal':
            if operation == 'chiffrer':
                Qx = int(params.get('Qx', 0))
                Qy = int(params.get('Qy', 0))
                resultat = ec_elgamal_chiffrer(message, Qx, Qy)
            else:
                k = int(params.get('k_prive', 0))
                resultat = ec_elgamal_dechiffrer(message, k)
            return jsonify({'resultat': resultat})
        
        else:
            return jsonify({'erreur': f'Algorithme inconnu: {algo}'}), 400
    
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/api/generer-cles', methods=['POST'])
@login_requis
def api_generer_cles():
    """Génère des clés pour les algorithmes asymétriques."""
    data = request.get_json()
    algo = data.get('algorithme', '').lower()
    
    try:
        if algo == 'rsa':
            cles = rsa_generer_cles(512)
            return jsonify({
                'e': str(cles['cle_publique']['e']),
                'n': str(cles['cle_publique']['n']),
                'd': str(cles['cle_privee']['d'])
            })
        
        elif algo == 'elgamal':
            cles = elgamal_generer_cles(256)
            return jsonify({
                'p': str(cles['cle_publique']['p']),
                'g': str(cles['cle_publique']['g']),
                'y': str(cles['cle_publique']['y']),
                'x': str(cles['cle_privee']['x'])
            })
        
        elif algo == 'ec_elgamal':
            cles = ec_elgamal_generer_cles()
            return jsonify({
                'Qx': str(cles['cle_publique']['Qx']),
                'Qy': str(cles['cle_publique']['Qy']),
                'k_prive': str(cles['cle_privee'])
            })
        
        else:
            return jsonify({'erreur': 'Algorithme non supporté'}), 400
    
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


# =============================================================================
# ROUTES ADMINISTRATION
# =============================================================================

@app.route('/admin/utilisateur/creer', methods=['POST'])
@admin_requis
def admin_creer_utilisateur():
    """Crée un nouvel utilisateur."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    
    if not all([username, email, password]):
        flash('Tous les champs sont obligatoires.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    mdp_hash = hacher_mot_de_passe(password)
    conn = get_db()
    
    try:
        conn.execute(
            "INSERT INTO utilisateurs (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, mdp_hash, role)
        )
        conn.commit()
        flash(f'Utilisateur {username} créé avec succès.', 'success')
    except sqlite3.IntegrityError:
        flash('Nom d\'utilisateur ou email déjà existant.', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/utilisateur/modifier/<int:user_id>', methods=['POST'])
@admin_requis
def admin_modifier_utilisateur(user_id):
    """Modifie un utilisateur existant."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    role = request.form.get('role', 'user')
    nouveau_mdp = request.form.get('password', '').strip()
    
    conn = get_db()
    
    try:
        if nouveau_mdp:
            mdp_hash = hacher_mot_de_passe(nouveau_mdp)
            conn.execute(
                "UPDATE utilisateurs SET username=?, email=?, role=?, password=? WHERE id=?",
                (username, email, role, mdp_hash, user_id)
            )
        else:
            conn.execute(
                "UPDATE utilisateurs SET username=?, email=?, role=? WHERE id=?",
                (username, email, role, user_id)
            )
        conn.commit()
        flash(f'Utilisateur {username} modifié.', 'success')
    except sqlite3.IntegrityError:
        flash('Nom d\'utilisateur ou email déjà existant.', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/utilisateur/supprimer/<int:user_id>', methods=['POST'])
@admin_requis
def admin_supprimer_utilisateur(user_id):
    """Supprime un utilisateur."""
    if user_id == session['user_id']:
        flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    user = conn.execute("SELECT username FROM utilisateurs WHERE id=?", (user_id,)).fetchone()
    
    if user:
        conn.execute("DELETE FROM utilisateurs WHERE id=?", (user_id,))
        conn.commit()
        flash(f'Utilisateur {user["username"]} supprimé.', 'success')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))


# =============================================================================
# ROUTE CHANGEMENT DE MOT DE PASSE (pour utilisateur connecté)
# =============================================================================

@app.route('/changer-mot-de-passe', methods=['POST'])
@login_requis
def changer_mot_de_passe():
    """
    Permet à un utilisateur de modifier son mot de passe.
    Vérifie l'ancien mot de passe avant de le changer.
    """
    ancien_mdp = request.form.get('ancien_mot_de_passe', '')
    nouveau_mdp = request.form.get('nouveau_mot_de_passe', '')
    confirmation = request.form.get('confirmation_mot_de_passe', '')
    
    # Variable pour suivre s'il y a des erreurs
    has_error = False
    
    # === Validation 1: Vérifier que tous les champs sont remplis ===
    if not ancien_mdp:
        flash('❌ Veuillez saisir votre ancien mot de passe.', 'danger')
        has_error = True
    if not nouveau_mdp:
        flash('❌ Veuillez saisir un nouveau mot de passe.', 'danger')
        has_error = True
    if not confirmation:
        flash('❌ Veuillez confirmer votre nouveau mot de passe.', 'danger')
        has_error = True
    
    if has_error:
        return redirect(url_for('dashboard'))
    
    # === Validation 2: Vérifier la longueur du nouveau mot de passe ===
    if len(nouveau_mdp) < 6:
        flash('❌ Le nouveau mot de passe doit contenir au moins 6 caractères.', 'danger')
        return redirect(url_for('dashboard'))
    
    # === Validation 3: Vérifier que l'ancien et le nouveau sont différents ===
    if ancien_mdp == nouveau_mdp:
        flash('❌ Le nouveau mot de passe doit être différent de l\'ancien.', 'danger')
        return redirect(url_for('dashboard'))
    
    # === Validation 4: Vérifier que les deux nouveaux mots de passe correspondent ===
    if nouveau_mdp != confirmation:
        flash('❌ Les deux nouveaux mots de passe ne correspondent pas.', 'danger')
        return redirect(url_for('dashboard'))
    
    # === Validation 5: Vérifier l'ancien mot de passe dans la base de données ===
    conn = get_db()
    user = conn.execute(
        "SELECT password FROM utilisateurs WHERE id = ?", (session['user_id'],)
    ).fetchone()
    
    if not user:
        flash('❌ Utilisateur non trouvé. Veuillez vous reconnecter.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Vérification de l'ancien mot de passe
    if not verifier_mot_de_passe(ancien_mdp, user['password']):
        flash('❌ Ancien mot de passe incorrect.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # === Tout est valide, on procède au changement ===
    nouveau_hash = hacher_mot_de_passe(nouveau_mdp)
    conn.execute(
        "UPDATE utilisateurs SET password = ? WHERE id = ?",
        (nouveau_hash, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    # Message de succès avec confirmation visuelle
    flash('✅ Votre mot de passe a été modifié avec succès !', 'success')
    return redirect(url_for('dashboard'))

# =============================================================================
# DÉMARRAGE
# =============================================================================

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("Application Cryptographie - Pr. Asmae EL KASSIRI")
    print("http://127.0.0.1:5000")
    print("Admin par défaut: admin / Admin@1234")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)