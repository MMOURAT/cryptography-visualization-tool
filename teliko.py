# -*- coding: utf-8 -*-
"""
crypto_total.py
Ενιαίο αρχείο: Caesar, Vigenere, Playfair (κλασικοί) + AES-GCM, RSA-OAEP, ECC (μοντέρνοι)
GUI (Tkinter) και βελτιωμένη κονσόλα.
Μηνύματα/σχόλια στα Ελληνικά.
"""

import sys
import os
import string
import datetime
import base64
import json
import secrets
import getpass

# Προσπαθούμε για χρώματα στην κονσόλα
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    def color(text, col):
        return col + text + Style.RESET_ALL
except Exception:
    def color(text, col=None):
        return text

# Προσπαθούμε να φορτώσουμε cryptography για σύγχρονους αλγορίθμους
_CRYPTO_OK = True
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
except Exception as e:
    _CRYPTO_OK = False
    _CRYPTO_ERR = e

# ---------------------------
#  ΚΛΑΣΣΙΚΟΙ ΑΛΓΟΡΙΘΜΟΙ
# ---------------------------

# ---------- CAESAR ----------
def caesar_encrypt(text, shift):
    alphabet = string.ascii_uppercase
    res = []
    for ch in text.upper():
        if ch in alphabet:
            res.append(alphabet[(alphabet.index(ch) + shift) % 26])
        else:
            res.append(ch)
    return "".join(res)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ---------- VIGENERE ----------
def generate_vigenere_key(text, key):
    key = key.upper()
    full = []
    k = 0
    for ch in text:
        if ch.isalpha():
            full.append(key[k % len(key)])
            k += 1
        else:
            full.append(ch)
    return "".join(full)

def vigenere_encrypt(text, key):
    t = text.upper()
    full_key = generate_vigenere_key(t, key)
    res = []
    for tc, kc in zip(t, full_key):
        if tc.isalpha():
            offset = (ord(tc) - ord('A') + (ord(kc) - ord('A'))) % 26
            res.append(chr(offset + ord('A')))
        else:
            res.append(tc)
    return "".join(res)

def vigenere_decrypt(text, key):
    t = text.upper()
    full_key = generate_vigenere_key(t, key)
    res = []
    for tc, kc in zip(t, full_key):
        if tc.isalpha():
            offset = (ord(tc) - ord('A') - (ord(kc) - ord('A'))) % 26
            res.append(chr(offset + ord('A')))
        else:
            res.append(tc)
    return "".join(res)

# ---------- PLAYFAIR ----------
def generate_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    used = []
    for ch in key:
        if ch.isalpha() and ch not in used:
            used.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            used.append(ch)
    matrix = [used[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, ch):
    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)
    return None

def prepare_playfair_text(text):
    cleaned = [c for c in text.upper().replace('J', 'I') if c.isalpha()]
    pairs = []
    i = 0
    while i < len(cleaned):
        a = cleaned[i]
        b = cleaned[i+1] if i+1 < len(cleaned) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    # ensure last pair padded if necessary
    if len(pairs) > 0 and len(pairs[-1]) == 1:
        last = pairs[-1][0]
        pairs[-1] = (last, 'X')
    return pairs

def playfair_encrypt(text, key):
    matrix = generate_playfair_matrix(key)
    pairs = prepare_playfair_text(text)
    res = []
    for a, b in pairs:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        if r1 == r2:
            res.append(matrix[r1][(c1 + 1) % 5])
            res.append(matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:
            res.append(matrix[(r1 + 1) % 5][c1])
            res.append(matrix[(r2 + 1) % 5][c2])
        else:
            res.append(matrix[r1][c2])
            res.append(matrix[r2][c1])
    return "".join(res)

def playfair_decrypt(text, key):
    matrix = generate_playfair_matrix(key)
    cleaned = [c for c in text.upper() if c.isalpha()]
    res = []
    for i in range(0, len(cleaned), 2):
        a = cleaned[i]
        b = cleaned[i+1] if i+1 < len(cleaned) else 'X'
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        if r1 == r2:
            res.append(matrix[r1][(c1 - 1) % 5])
            res.append(matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            res.append(matrix[(r1 - 1) % 5][c1])
            res.append(matrix[(r2 - 1) % 5][c2])
        else:
            res.append(matrix[r1][c2])
            res.append(matrix[r2][c1])
    return "".join(res)

# ---------------------------
#  ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ
# ---------------------------

def save_result_to_file(filename, algorithm, params, message, encrypted, decrypted):
    """Αποθηκεύει αποτέλεσμα σε αρχείο .txt (προσθέτει timestamp)."""
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write("==== Κρυπτογράφηση ====\n")
            f.write(f"Ημερομηνία: {datetime.datetime.now().isoformat()}\n")
            f.write(f"Αλγόριθμος: {algorithm}\n")
            f.write(f"Παράμετροι: {params}\n")
            f.write(f"Μήνυμα: {message}\n")
            f.write(f"Κρυπτογραφημένο: {encrypted}\n")
            f.write(f"Αποκρυπτογραφημένο: {decrypted}\n")
            f.write("\n")
        return True, None
    except Exception as e:
        return False, str(e)

def short_description(alg):
    if alg == 'caesar':
        return ("Caesar: Μετατοπίζει κάθε γράμμα κατά έναν αριθμό θέσεων στο αλφάβητο.\n"
                "Πολύ απλός αλγόριθμος, καλός για εκπαιδευτικούς σκοπούς.")
    if alg == 'vigenere':
        return ("Vigenère: Χρησιμοποιεί λέξη-κλειδί. Κάθε γράμμα του κλειδιού\n"
                "ορίζει τη μετατόπιση για το αντίστοιχο γράμμα του μηνύματος.")
    if alg == 'playfair':
        return ("Playfair: Χρησιμοποιεί πίνακα 5x5 βασισμένο σε κλειδί.\n"
                "Κρυπτογραφεί γράμματα σε ζεύγη (digraphs).")
    if alg == 'aes':
        return ("AES-GCM: Σύγχρονη συμμετρική κρυπτογράφηση με αυθεντικοποίηση (GCM).\n"
                "Χρησιμοποιείται password-derived key (PBKDF2) ή ωμό κλειδί σε hex.")
    if alg == 'rsa':
        return ("RSA (OAEP): Ασύμμετρη κρυπτογράφηση με OAEP padding.\n"
                "Υποστηρίζει δημιουργία ζεύγους κλειδιών (PEM).")
    if alg == 'ecc':
        return ("ECC (ECDH + AES-GCM): Υβριδική μέθοδος: ECDH για κοινό κλειδί,\n"
                "κατόπιν AES-GCM για το ίδιο το μήνυμα. Curve: SECP256R1.")
    return ""

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

# ---------------------------
#  ΣΥΓΧΡΟΝΟΙ ΑΛΓΟΡΙΘΜΟΙ (AES, RSA, ECC)
# ---------------------------

# AES-GCM (key derived via PBKDF2 ή raw key hex)
def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 200000):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def aes_encrypt(plaintext: str, password: str = None, raw_key_hex: str = None):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    if raw_key_hex:
        key = bytes.fromhex(raw_key_hex)
        salt = None
    elif password is not None:
        key, salt = derive_key_from_password(password)
    else:
        raise ValueError("Πρέπει να δοθεί password ή raw_key_hex")
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    pt = plaintext.encode('utf-8')
    ct = aesgcm.encrypt(nonce, pt, None)
    payload = {
        "salt": b64(salt) if salt is not None else None,
        "nonce": b64(nonce),
        "ciphertext": b64(ct)
    }
    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')

def aes_decrypt(payload_b64: str, password: str = None, raw_key_hex: str = None):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    raw = base64.b64decode(payload_b64.encode('utf-8'))
    payload = json.loads(raw.decode('utf-8'))
    salt_b64 = payload.get("salt")
    nonce = ub64(payload["nonce"])
    ct = ub64(payload["ciphertext"])
    if raw_key_hex:
        key = bytes.fromhex(raw_key_hex)
    elif password is not None:
        if salt_b64 is None:
            raise ValueError("Το payload δεν περιέχει salt για derivation.")
        salt = ub64(salt_b64)
        key, _ = derive_key_from_password(password, salt=salt)
    else:
        raise ValueError("Πρέπει να δοθεί password ή raw_key_hex")
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("Αποτυχημένη επαλήθευση/συμπιεστής (λάθος κλειδί ή αλλοιωμένο ciphertext).")
    return pt.decode('utf-8')

# RSA (OAEP)
def rsa_generate_keys(key_size: int = 2048):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def rsa_encrypt(plaintext: str, public_pem: str):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    pub = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
    ct = pub.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return b64(ct)

def rsa_decrypt(ciphertext_b64: str, private_pem: str):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    priv = serialization.load_pem_private_key(private_pem.encode('utf-8'), password=None, backend=default_backend())
    ct = ub64(ciphertext_b64)
    pt = priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt.decode('utf-8')

# ECC (ECDH ephemeral + AES-GCM)
def ecc_generate_keys():
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem.decode('utf-8'), pub_pem.decode('utf-8')

def ecc_encrypt(plaintext: str, recipient_public_pem: str):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    recipient_pub = serialization.load_pem_public_key(recipient_public_pem.encode('utf-8'), backend=default_backend())
    eph_priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh-aesgcm", backend=default_backend())
    key = hkdf.derive(shared)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    eph_pub_pem = eph_priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    payload = {
        "ephemeral_pub": b64(eph_pub_pem),
        "nonce": b64(nonce),
        "ciphertext": b64(ct)
    }
    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')

def ecc_decrypt(payload_b64: str, recipient_private_pem: str):
    if not _CRYPTO_OK:
        raise RuntimeError(f"Απαιτείται η βιβλιοθήκη 'cryptography' ({_CRYPTO_ERR})")
    raw = base64.b64decode(payload_b64.encode('utf-8'))
    payload = json.loads(raw.decode('utf-8'))
    eph_pub_pem = ub64(payload['ephemeral_pub'])
    nonce = ub64(payload['nonce'])
    ct = ub64(payload['ciphertext'])
    recipient_priv = serialization.load_pem_private_key(recipient_private_pem.encode('utf-8'), password=None, backend=default_backend())
    eph_pub = serialization.load_pem_public_key(eph_pub_pem, backend=default_backend())
    shared = recipient_priv.exchange(ec.ECDH(), eph_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh-aesgcm", backend=default_backend())
    key = hkdf.derive(shared)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("Αποτυχία επαλήθευσης AES-GCM (λάθος ή αλλοιωμένο ciphertext).")
    return pt.decode('utf-8')

# ---------------------------
#  ΚΟΝΣΟΛΑ (ΕΝΙΑΙΑ)
# ---------------------------

def console_mode():
    print("\n" + "="*60)
    print("  Crypto Total — Κονσόλα")
    print("="*60)
    if not _CRYPTO_OK:
        print(color("Σημείωση: Η βιβλιοθήκη 'cryptography' ΔΕΝ είναι διαθέσιμη.", Fore.YELLOW if 'Fore' in globals() else None))
        print("Οι λειτουργίες AES/RSA/ECC δεν θα λειτουργήσουν χωρίς αυτήν.")
        print("Σφάλμα φόρτωσης:", getattr(sys.modules.get('cryptography'), '__dict__', {}).get('_CRYPTO_ERR', _CRYPTO_ERR) if '_CRYPTO_ERR' in globals() else _CRYPTO_ERR)
    while True:
        print("\nΕπίλεξε αλγόριθμο:")
        print("1) Caesar")
        print("2) Vigenère")
        print("3) Playfair")
        print("4) AES-GCM (συμμετρικό)")
        print("5) RSA (OAEP)")
        print("6) ECC (ECDH + AES-GCM, υβριδικό)")
        print("7) Έξοδος")
        choice = input("Διάλεξε (1-7): ").strip()

        if choice == '7':
            print(color("Έξοδος. Καλή συνέχεια!", Fore.GREEN if 'Fore' in globals() else None))
            break

        if choice not in ('1','2','3','4','5','6'):
            print(color("Μη έγκυρη επιλογή. Δοκίμασε πάλι.", Fore.RED if 'Fore' in globals() else None))
            continue

        if choice == '1':
            print("\n" + short_description('caesar'))
            message = input("\nΔώσε το μήνυμα: ")
            while True:
                s = input("Δώσε τη μετατόπιση (πλήρες ακέραιο): ").strip()
                try:
                    shift = int(s)
                    break
                except ValueError:
                    print(color("Η μετατόπιση πρέπει να είναι ακέραιος αριθμός.", Fore.YELLOW if 'Fore' in globals() else None))
            encrypted = caesar_encrypt(message, shift)
            decrypted = caesar_decrypt(encrypted, shift)
            print(color("\nΚρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), encrypted)
            print(color("Αποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), decrypted)
            save = input("\nΘες να αποθηκεύσω σε αρχείο; (y/n): ").strip().lower()
            if save == 'y':
                fname = input("Όνομα αρχείου (π.χ. results.txt): ").strip() or "results.txt"
                ok, err = save_result_to_file(fname, "Caesar", f"shift={shift}", message, encrypted, decrypted)
                print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))

        elif choice == '2':
            print("\n" + short_description('vigenere'))
            message = input("\nΔώσε το μήνυμα: ")
            while True:
                key = input("Δώσε το κλειδί (μόνο γράμματα): ").strip()
                if key.isalpha():
                    break
                print(color("Το κλειδί πρέπει να περιέχει μόνο γράμματα (A-Z).", Fore.YELLOW if 'Fore' in globals() else None))
            encrypted = vigenere_encrypt(message, key)
            decrypted = vigenere_decrypt(encrypted, key)
            print(color("\nΚρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), encrypted)
            print(color("Αποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), decrypted)
            save = input("\nΘες να αποθηκεύσω σε αρχείο; (y/n): ").strip().lower()
            if save == 'y':
                fname = input("Όνομα αρχείου (π.χ. results.txt): ").strip() or "results.txt"
                ok, err = save_result_to_file(fname, "Vigenere", f"key={key}", message, encrypted, decrypted)
                print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))

        elif choice == '3':
            print("\n" + short_description('playfair'))
            message = input("\nΔώσε το μήνυμα: ")
            while True:
                key = input("Δώσε το κλειδί Playfair (γράμματα): ").strip()
                if key.isalpha():
                    break
                print(color("Το κλειδί πρέπει να περιέχει μόνο γράμματα.", Fore.YELLOW if 'Fore' in globals() else None))
            encrypted = playfair_encrypt(message, key)
            decrypted = playfair_decrypt(encrypted, key)
            print(color("\nΚρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), encrypted)
            print(color("Αποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None), decrypted)
            save = input("\nΘες να αποθηκεύσω σε αρχείο; (y/n): ").strip().lower()
            if save == 'y':
                fname = input("Όνομα αρχείου (π.χ. results.txt): ").strip() or "results.txt"
                ok, err = save_result_to_file(fname, "Playfair", f"key={key}", message, encrypted, decrypted)
                print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))

        elif choice == '4':
            print("\n" + short_description('aes'))
            if not _CRYPTO_OK:
                print(color("Δεν είναι διαθέσιμη η βιβλιοθήκη 'cryptography'.", Fore.RED if 'Fore' in globals() else None))
                continue
            msg = input("\nΔώσε το μήνυμα: ")
            print("Μέθοδοι κλειδιού:")
            print("1) Password (PBKDF2)")
            print("2) Raw key (hex, 64 hex chars για AES-256)")
            m = input("Διάλεξε (1-2): ").strip()
            try:
                if m == '1':
                    pw = getpass.getpass("Δώσε password (δεν εμφανίζεται): ")
                    enc = aes_encrypt(msg, password=pw)
                    dec = aes_decrypt(enc, password=pw)
                    print(color("\nΚρυπτογραφημένο (base64 JSON):", Fore.CYAN if 'Fore' in globals() else None))
                    print(enc)
                    print(color("\nΑποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None))
                    print(dec)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "AES-GCM", "password-derived", msg, enc, dec)
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
                else:
                    rk = input("Δώσε raw key σε hex (64 hex chars για AES-256): ").strip()
                    enc = aes_encrypt(msg, raw_key_hex=rk)
                    dec = aes_decrypt(enc, raw_key_hex=rk)
                    print(color("\nΚρυπτογραφημένο (base64 JSON):", Fore.CYAN if 'Fore' in globals() else None))
                    print(enc)
                    print(color("\nΑποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None))
                    print(dec)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "AES-GCM", "raw_key_hex", msg, enc, dec)
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
            except Exception as e:
                print(color(f"Σφάλμα: {e}", Fore.RED if 'Fore' in globals() else None))

        elif choice == '5':
            print("\n" + short_description('rsa'))
            if not _CRYPTO_OK:
                print(color("Δεν είναι διαθέσιμη η βιβλιοθήκη 'cryptography'.", Fore.RED if 'Fore' in globals() else None))
                continue
            print("Επιλογές:")
            print("1) Δημιουργία νέου ζεύγους κλειδιών (RSA 2048)")
            print("2) Κρυπτογράφηση με δημόσιο PEM")
            print("3) Αποκρυπτογράφηση με ιδιωτικό PEM")
            sub = input("Διάλεξε (1-3): ").strip()
            try:
                if sub == '1':
                    priv_pem, pub_pem = rsa_generate_keys()
                    print(color("\nΙδιωτικό PEM:", Fore.CYAN if 'Fore' in globals() else None))
                    print(priv_pem)
                    print(color("\nΔημόσιο PEM:", Fore.CYAN if 'Fore' in globals() else None))
                    print(pub_pem)
                    save = input("\nΑποθήκευση σε αρχεία; (y/n): ").strip().lower()
                    if save == 'y':
                        ppriv = input("Όνομα αρχείου ιδιωτικού (π.χ. rsa_priv.pem): ").strip() or "rsa_priv.pem"
                        ppub = input("Όνομα αρχείου δημόσιου (π.χ. rsa_pub.pem): ").strip() or "rsa_pub.pem"
                        open(ppriv, 'w', encoding='utf-8').write(priv_pem)
                        open(ppub, 'w', encoding='utf-8').write(pub_pem)
                        print(color(f"Αποθηκεύτηκαν: {ppriv}, {ppub}", Fore.GREEN if 'Fore' in globals() else None))
                elif sub == '2':
                    print("Επικόλλησε δημόσιο PEM (τελείωσε με κενή γραμμή):")
                    lines = []
                    while True:
                        l = input()
                        if l.strip() == "":
                            break
                        lines.append(l)
                    pub = "\n".join(lines)
                    if "-----BEGIN" not in pub:
                        print(color("Μη έγκυρο PEM.", Fore.RED if 'Fore' in globals() else None))
                        continue
                    msg = input("Δώσε το μήνυμα προς κρυπτογράφηση: ")
                    ct = rsa_encrypt(msg, pub)
                    print(color("\nΚρυπτογραφημένο (base64):", Fore.CYAN if 'Fore' in globals() else None))
                    print(ct)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "RSA-OAEP", "public_pem", msg, ct, "")
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
                elif sub == '3':
                    print("Επικόλλησε ιδιωτικό PEM (τελείωσε με κενή γραμμή):")
                    lines = []
                    while True:
                        l = input()
                        if l.strip() == "":
                            break
                        lines.append(l)
                    priv = "\n".join(lines)
                    if "-----BEGIN" not in priv:
                        print(color("Μη έγκυρο PEM.", Fore.RED if 'Fore' in globals() else None))
                        continue
                    ct = input("Δώσε ciphertext (base64): ").strip()
                    pt = rsa_decrypt(ct, priv)
                    print(color("\nΑποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None))
                    print(pt)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "RSA-OAEP", "private_pem", pt, ct, pt)
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
            except Exception as e:
                print(color(f"Σφάλμα RSA: {e}", Fore.RED if 'Fore' in globals() else None))

        elif choice == '6':
            print("\n" + short_description('ecc'))
            if not _CRYPTO_OK:
                print(color("Δεν είναι διαθέσιμη η βιβλιοθήκη 'cryptography'.", Fore.RED if 'Fore' in globals() else None))
                continue
            print("Επιλογές:")
            print("1) Δημιουργία ECC ζεύγους (PEM)")
            print("2) Κρυπτογράφηση με δημόσιο PEM (υβριδικό)")
            print("3) Αποκρυπτογράφηση με ιδιωτικό PEM")
            sub = input("Διάλεξε (1-3): ").strip()
            try:
                if sub == '1':
                    priv_pem, pub_pem = ecc_generate_keys()
                    print(color("\nΙδιωτικό PEM:", Fore.CYAN if 'Fore' in globals() else None))
                    print(priv_pem)
                    print(color("\nΔημόσιο PEM:", Fore.CYAN if 'Fore' in globals() else None))
                    print(pub_pem)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        ppriv = input("Όνομα αρχείου ιδιωτικού (π.χ. ecc_priv.pem): ").strip() or "ecc_priv.pem"
                        ppub = input("Όνομα αρχείου δημόσιου (π.χ. ecc_pub.pem): ").strip() or "ecc_pub.pem"
                        open(ppriv, 'w', encoding='utf-8').write(priv_pem)
                        open(ppub, 'w', encoding='utf-8').write(pub_pem)
                        print(color(f"Αποθηκεύτηκαν: {ppriv}, {ppub}", Fore.GREEN if 'Fore' in globals() else None))
                elif sub == '2':
                    print("Επικόλλησε δημόσιο PEM παραλήπτη (τελείωσε με κενή γραμμή):")
                    lines = []
                    while True:
                        l = input()
                        if l.strip() == "":
                            break
                        lines.append(l)
                    pub = "\n".join(lines)
                    if "-----BEGIN" not in pub:
                        print(color("Μη έγκυρο PEM.", Fore.RED if 'Fore' in globals() else None))
                        continue
                    msg = input("Δώσε το μήνυμα προς κρυπτογράφηση: ")
                    ct = ecc_encrypt(msg, pub)
                    print(color("\nΚρυπτογραφημένο (base64 JSON):", Fore.CYAN if 'Fore' in globals() else None))
                    print(ct)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "ECC-HYBRID", "recipient_public_pem", msg, ct, "")
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
                elif sub == '3':
                    print("Επικόλλησε ιδιωτικό PEM (τελείωσε με κενή γραμμή):")
                    lines = []
                    while True:
                        l = input()
                        if l.strip() == "":
                            break
                        lines.append(l)
                    priv = "\n".join(lines)
                    if "-----BEGIN" not in priv:
                        print(color("Μη έγκυρο PEM.", Fore.RED if 'Fore' in globals() else None))
                        continue
                    ct = input("Δώσε ciphertext (base64 JSON): ").strip()
                    pt = ecc_decrypt(ct, priv)
                    print(color("\nΑποκρυπτογραφημένο:", Fore.CYAN if 'Fore' in globals() else None))
                    print(pt)
                    save = input("\nΑποθήκευση; (y/n): ").strip().lower()
                    if save == 'y':
                        fname = input("Όνομα αρχείου: ").strip() or "results.txt"
                        ok, err = save_result_to_file(fname, "ECC-HYBRID", "recipient_private_pem", pt, ct, pt)
                        print(color(f"Αποθήκευσε: {fname}" if ok else f"Σφάλμα: {err}", Fore.GREEN if ok else Fore.RED if 'Fore' in globals() else None))
            except Exception as e:
                print(color(f"Σφάλμα ECC: {e}", Fore.RED if 'Fore' in globals() else None))

# ---------------------------
#  GUI (Tkinter) - ΕΝΙΑΙΟ
# ---------------------------

def gui_mode():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog, scrolledtext
    except Exception as e:
        print(color("Σφάλμα: δεν βρέθηκε βιβλιοθήκη Tkinter.", Fore.RED if 'Fore' in globals() else None))
        print("Σφάλμα φορτώματος Tkinter:", e)
        return

    root = tk.Tk()
    root.title("Crypto Total — Caesar/Vigenere/Playfair + AES/RSA/ECC")

    main = ttk.Frame(root, padding=12)
    main.grid(row=0, column=0, sticky="nsew")

    ttk.Label(main, text="Επίλεξε αλγόριθμο:").grid(row=0, column=0, sticky='w')
    alg_var = tk.StringVar(value='caesar')
    ttk.Radiobutton(main, text="Caesar", variable=alg_var, value='caesar', command=lambda: update_description()).grid(row=1, column=0, sticky='w')
    ttk.Radiobutton(main, text="Vigenère", variable=alg_var, value='vigenere', command=lambda: update_description()).grid(row=1, column=1, sticky='w')
    ttk.Radiobutton(main, text="Playfair", variable=alg_var, value='playfair', command=lambda: update_description()).grid(row=1, column=2, sticky='w')
    ttk.Radiobutton(main, text="AES-GCM", variable=alg_var, value='aes', command=lambda: update_description()).grid(row=2, column=0, sticky='w')
    ttk.Radiobutton(main, text="RSA-OAEP", variable=alg_var, value='rsa', command=lambda: update_description()).grid(row=2, column=1, sticky='w')
    ttk.Radiobutton(main, text="ECC (ECDH+AES)", variable=alg_var, value='ecc', command=lambda: update_description()).grid(row=2, column=2, sticky='w')

    ttk.Label(main, text="Περιγραφή:").grid(row=3, column=0, sticky='w')
    desc_text = tk.Text(main, width=80, height=4, wrap='word', state='disabled')
    desc_text.grid(row=4, column=0, columnspan=3, pady=(6,12))

    ttk.Label(main, text="Μήνυμα:").grid(row=5, column=0, sticky='w')
    msg_box = scrolledtext.ScrolledText(main, width=80, height=6)
    msg_box.grid(row=6, column=0, columnspan=3, pady=(0,8))

    ttk.Label(main, text="Παράμετροι / Κλειδί / PEM:").grid(row=7, column=0, sticky='w')
    param_entry = ttk.Entry(main, width=80)
    param_entry.grid(row=8, column=0, columnspan=3, sticky='w')

    result_enc_var = tk.StringVar()
    result_dec_var = tk.StringVar()

    def update_description():
        sel = alg_var.get()
        desc = short_description(sel)
        if sel == 'caesar':
            desc += "\n\nΑίτημα: Δώσε μήνυμα και αριθμητική μετατόπιση στο πεδίο 'Παράμετροι' (π.χ. 3)."
        elif sel == 'vigenere':
            desc += "\n\nΑίτημα: Δώσε μήνυμα και λέξη-κλειδί στο πεδίο 'Παράμετροι'."
        elif sel == 'playfair':
            desc += "\n\nΑίτημα: Δώσε μήνυμα και λέξη-κλειδί (Playfair) στο πεδίο 'Παράμετροι'."
        elif sel == 'aes':
            desc += "\n\nΓια AES: βάλτε 'pw:yourpassword' ή 'raw:hexkey' στα 'Παράμετροι'."
        elif sel == 'rsa':
            desc += "\n\nΓια RSA: για κρυπτογράφηση επικόλλησε δημόσιο PEM στα 'Παράμετροι'. Για αποκρυπτογράφηση επικόλλησε ιδιωτικό PEM."
        elif sel == 'ecc':
            desc += "\n\nΓια ECC: για κρυπτογράφηση επικόλλησε δημόσιο PEM στα 'Παράμετροι'. Για αποκρυπτογράφηση επικόλλησε ιδιωτικό PEM."
        desc_text.config(state='normal')
        desc_text.delete('1.0', tk.END)
        desc_text.insert(tk.END, desc)
        desc_text.config(state='disabled')

    def do_encrypt():
        alg = alg_var.get()
        msg = msg_box.get("1.0", tk.END).strip()
        params = param_entry.get().strip()
        if not msg:
            messagebox.showwarning("Λείπει μήνυμα", "Δώσε το μήνυμα πρώτα.")
            return
        try:
            if alg == 'caesar':
                shift = int(params)
                enc = caesar_encrypt(msg, shift)
                dec = caesar_decrypt(enc, shift)
            elif alg == 'vigenere':
                key = params
                if not key.isalpha():
                    messagebox.showwarning("Μη έγκυρο κλειδί", "Το κλειδί πρέπει να είναι μόνο γράμματα.")
                    return
                enc = vigenere_encrypt(msg, key)
                dec = vigenere_decrypt(enc, key)
            elif alg == 'playfair':
                key = params
                if not key.isalpha():
                    messagebox.showwarning("Μη έγκυρο κλειδί", "Το κλειδί πρέπει να είναι μόνο γράμματα.")
                    return
                enc = playfair_encrypt(msg, key)
                dec = playfair_decrypt(enc, key)
            elif alg == 'aes':
                if not _CRYPTO_OK:
                    messagebox.showerror("Εξαρτήσεις", f"Η βιβλιοθήκη 'cryptography' δεν είναι διαθέσιμη:\n{_CRYPTO_ERR}")
                    return
                if params.startswith("pw:"):
                    pw = params[3:]
                    enc = aes_encrypt(msg, password=pw)
                    dec = aes_decrypt(enc, password=pw)
                elif params.startswith("raw:"):
                    rk = params[4:]
                    enc = aes_encrypt(msg, raw_key_hex=rk)
                    dec = aes_decrypt(enc, raw_key_hex=rk)
                else:
                    messagebox.showinfo("Σημείωση", "Για AES βάλτε παράμετρο στο format 'pw:yourpassword' ή 'raw:hexkey'")
                    return
            elif alg == 'rsa':
                if not _CRYPTO_OK:
                    messagebox.showerror("Εξαρτήσεις", f"Η βιβλιοθήκη 'cryptography' δεν είναι διαθέσιμη:\n{_CRYPTO_ERR}")
                    return
                pub = params
                enc = rsa_encrypt(msg, pub)
                dec = ""
            elif alg == 'ecc':
                if not _CRYPTO_OK:
                    messagebox.showerror("Εξαρτήσεις", f"Η βιβλιοθήκη 'cryptography' δεν είναι διαθέσιμη:\n{_CRYPTO_ERR}")
                    return
                pub = params
                enc = ecc_encrypt(msg, pub)
                dec = ""
            else:
                return
        except Exception as e:
            messagebox.showerror("Σφάλμα", f"Σφάλμα κατά την επεξεργασία: {e}")
            return
        result_enc_var.set(enc)
        result_dec_var.set(dec)

    def do_decrypt():
        alg = alg_var.get()
        ct = result_enc_var.get().strip()
        params = param_entry.get().strip()
        if not ct:
            messagebox.showwarning("Δεν υπάρχει ciphertext", "Πρώτα κρυπτογραφήστε ή επικολλήστε ciphertext.")
            return
        try:
            if alg == 'caesar':
                shift = int(params)
                dec = caesar_decrypt(ct, shift)
            elif alg == 'vigenere':
                key = params
                dec = vigenere_decrypt(ct, key)
            elif alg == 'playfair':
                key = params
                dec = playfair_decrypt(ct, key)
            elif alg == 'aes':
                if params.startswith("pw:"):
                    pw = params[3:]
                    dec = aes_decrypt(ct, password=pw)
                elif params.startswith("raw:"):
                    rk = params[4:]
                    dec = aes_decrypt(ct, raw_key_hex=rk)
                else:
                    messagebox.showinfo("Σημείωση", "Για AES βάλτε παράμετρο στο format 'pw:yourpassword' ή 'raw:hexkey'")
                    return
            elif alg == 'rsa':
                priv = params
                dec = rsa_decrypt(ct, priv)
            elif alg == 'ecc':
                priv = params
                dec = ecc_decrypt(ct, priv)
            else:
                return
        except Exception as e:
            messagebox.showerror("Σφάλμα αποκρυπτογράφησης", f"{e}")
            return
        result_dec_var.set(dec)

    def do_save():
        alg = alg_var.get()
        msg = msg_box.get("1.0", tk.END).strip()
        enc = result_enc_var.get()
        dec = result_dec_var.get()
        if not enc:
            messagebox.showinfo("Δεν υπάρχει αποτέλεσμα", "Πρώτα κάνε κρυπτογράφηση για να αποθηκεύσεις.")
            return
        fpath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not fpath:
            return
        params = param_entry.get().strip()
        ok, err = save_result_to_file(fpath, alg.upper(), params, msg, enc, dec)
        if ok:
            messagebox.showinfo("Αποθηκεύτηκε", f"Αποθηκεύτηκε το αποτέλεσμα στο:\n{fpath}")
        else:
            messagebox.showerror("Σφάλμα Αποθήκευσης", f"Σφάλμα: {err}")

    ttk.Button(main, text="Κρυπτογράφηση", command=do_encrypt).grid(row=9, column=0, pady=(8,4))
    ttk.Button(main, text="Αποκρυπτογράφηση", command=do_decrypt).grid(row=9, column=1, pady=(8,4))
    ttk.Button(main, text="Αποθήκευση", command=do_save).grid(row=9, column=2, pady=(8,4))

    ttk.Label(main, text="Κρυπτογραφημένο:").grid(row=10, column=0, sticky='w', pady=(8,0))
    ttk.Entry(main, textvariable=result_enc_var, width=80).grid(row=11, column=0, columnspan=3, sticky='w')
    ttk.Label(main, text="Αποκρυπτογραφημένο:").grid(row=12, column=0, sticky='w', pady=(8,0))
    ttk.Entry(main, textvariable=result_dec_var, width=80).grid(row=13, column=0, columnspan=3, sticky='w')

    update_description()
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    root.mainloop()

# ---------------------------
#  MAIN
# ---------------------------

def main():
    print("Crypto Total — Επιλογή λειτουργίας")
    print("1) Λειτουργία κονσόλας (βελτιωμένη)")
    print("2) Γραφικό περιβάλλον (GUI)")
    sel = input("Διάλεξε 1 ή 2: ").strip()
    if sel == '1':
        console_mode()
    elif sel == '2':
        gui_mode()
    else:
        print("Μη έγκυρη επιλογή. Τερματισμός.")

if __name__ == '__main__':
    main()
