#!/usr/bin/env python3
"""
generate_keys.py
Generates RSA key pairs for the SecureBox project:
- owner_private.pem / owner_public.pem (used to decrypt AES keys & sign ledger entries)
- share_private.pem / share_public.pem (optional: for multi-user scenarios)
"""
from Crypto.PublicKey import RSA
import os

KEY_DIR = "keys"
KEY_SIZE = 2048

def write_key(key, path):
    with open(path, "wb") as f:
        f.write(key.export_key())

def main():
    os.makedirs(KEY_DIR, exist_ok=True)

    # Primary owner keypair (used by the user who can decrypt files)
    owner_key = RSA.generate(KEY_SIZE)
    write_key(owner_key, os.path.join(KEY_DIR, "owner_private.pem"))
    write_key(owner_key.publickey(), os.path.join(KEY_DIR, "owner_public.pem"))

    # Secondary / sharing keypair (optional, useful for sharing workflows)
    share_key = RSA.generate(KEY_SIZE)
    write_key(share_key, os.path.join(KEY_DIR, "share_private.pem"))
    write_key(share_key.publickey(), os.path.join(KEY_DIR, "share_public.pem"))

    print(f"Generated RSA key pairs in '{KEY_DIR}/'.")
    print("Files created:")
    print(" - owner_private.pem, owner_public.pem")
    print(" - share_private.pem, share_public.pem (optional)")

if __name__ == "__main__":
    main()
