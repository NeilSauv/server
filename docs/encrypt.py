#!/usr/bin/env python3
# encrypt_resources.py
import os
import argparse
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(key: bytes, in_path: str, out_path: str):
    # Génère une nonce unique
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    with open(in_path, 'rb') as f:
        plaintext = f.read()
    # chiffrer (ciphertext contient déjà le tag GCM à la fin)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # On écrit nonce||ciphertext
    with open(out_path, 'wb') as f:
        f.write(nonce + ciphertext)
    print(f"Encrypté {in_path} → {out_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Chiffre des fichiers en AES-256-GCM pour votre extension VSCode"
    )
    parser.add_argument(
        "-k", "--key",
        help="Clé en base64 (256 bits). Si absent, une clé aléatoire est générée et affichée.",
        default=None
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Liste des fichiers à chiffrer"
    )
    parser.add_argument(
        "-o", "--out-dir",
        default="encrypted",
        help="Répertoire de sortie pour les .enc"
    )
    args = parser.parse_args()

    # Clé AES-256
    if args.key:
        key = base64.b64decode(args.key)
        if len(key) != 32:
            raise ValueError("La clé doit faire 32 octets (base64 sur 256 bits).")
    else:
        key = AESGCM.generate_key(bit_length=256)
        print("Clé générée (base64) :", base64.b64encode(key).decode())

    os.makedirs(args.out_dir, exist_ok=True)

    for path in args.files:
        filename = os.path.basename(path) + ".enc"
        out_path = os.path.join(args.out_dir, filename)
        encrypt_file(key, path, out_path)

if __name__ == "__main__":
    main()
