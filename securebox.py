#!/usr/bin/env python3
"""
securebox.py
Command-line tool to:
- encrypt and store files in the vault/
- decrypt and retrieve files from the vault/
- maintain ledger.json (tamper-evident chain of records)
- verify integrity and detect suspicious access attempts

Usage:
    python securebox.py init
    python securebox.py store path/to/plainfile.txt
    python securebox.py retrieve filename.enc path/to/output.txt
    python securebox.py list
    python securebox.py verify filename.enc
    python securebox.py ledger
"""
import os
import sys
import json
import base64
from datetime import datetime
from typing import Dict, Any

from crypto_utils import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    rsa_wrap_key,
    rsa_unwrap_key,
    sign_bytes,
    verify_signature,
    sha256_bytes
)

# Configuration
KEY_DIR = "keys"
VAULT_DIR = "vault"
LEDGER_FILE = "ledger.json"
LOG_FILE = "intrusion.log"

OWNER_PRIV_PATH = os.path.join(KEY_DIR, "owner_private.pem")
OWNER_PUB_PATH = os.path.join(KEY_DIR, "owner_public.pem")

# Ensure directories
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

# ---------- Ledger helpers ----------
def load_ledger() -> Dict[str, Any]:
    if not os.path.exists(LEDGER_FILE):
        return {"chain": []}
    with open(LEDGER_FILE, "r") as f:
        return json.load(f)

def save_ledger(ledger: Dict[str, Any]):
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)

def append_ledger_entry(entry: Dict[str, Any], owner_priv_pem: bytes):
    ledger = load_ledger()
    prev_hash = ledger["chain"][-1]["entry_hash"] if ledger["chain"] else ""
    entry["prev_hash"] = prev_hash
    # compute entry hash (hash of canonical json)
    entry_json = json.dumps(entry, sort_keys=True).encode()
    entry_hash = sha256_bytes(entry_json)
    entry["entry_hash"] = entry_hash
    # sign entry
    signature = sign_bytes(entry_json, owner_priv_pem)
    entry["signature"] = base64.b64encode(signature).decode()
    ledger["chain"].append(entry)
    save_ledger(ledger)

# ---------- Intrusion logging ----------
def log_intrusion(message: str):
    ts = datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {message}\n")

# ---------- Core operations ----------
def init_check():
    if not os.path.exists(OWNER_PRIV_PATH) or not os.path.exists(OWNER_PUB_PATH):
        print("Owner keys not found. Run generate_keys.py first to create key pairs.")
        sys.exit(1)

def store_file(path: str):
    init_check()
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return

    # Load owner's public key to wrap AES key
    with open(OWNER_PUB_PATH, "rb") as f:
        owner_pub = f.read()
    with open(OWNER_PRIV_PATH, "rb") as f:
        owner_priv = f.read()

    # Read plaintext
    with open(path, "rb") as f:
        plaintext = f.read()

    # Generate AES key and encrypt
    aes_key = generate_aes_key()
    nonce, ciphertext, tag = aes_encrypt(plaintext, aes_key)

    # Wrap AES key
    wrapped_key = rsa_wrap_key(aes_key, owner_pub)

    # Compose storage blob: wrapped_key || nonce || tag || ciphertext
    fname = os.path.basename(path) + ".enc"
    out_path = os.path.join(VAULT_DIR, fname)
    with open(out_path, "wb") as f:
        # we will store in base64-encoded JSON for readability/portability
        blob = {
            "wrapped_key": base64.b64encode(wrapped_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "original_name": os.path.basename(path),
            "stored_at": datetime.utcnow().isoformat() + "Z"
        }
        f.write(json.dumps(blob).encode())

    # Create ledger entry
    entry = {
        "action": "store",
        "file": fname,
        "original_name": os.path.basename(path),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "blob_sha256": sha256_bytes(json.dumps(blob, sort_keys=True).encode())
    }
    append_ledger_entry(entry, owner_priv)
    print(f"[+] Stored encrypted file: {out_path}")
    print("[+] Ledger updated.")

def retrieve_file(enc_filename: str, out_path: str):
    init_check()
    enc_full = os.path.join(VAULT_DIR, enc_filename)
    if not os.path.exists(enc_full):
        print(f"Encrypted file not found: {enc_full}")
        return

    with open(OWNER_PRIV_PATH, "rb") as f:
        owner_priv = f.read()
    with open(enc_full, "rb") as f:
        blob_json = f.read()
    try:
        blob = json.loads(blob_json)
    except Exception as e:
        print("Failed to parse encrypted blob:", e)
        return

    try:
        wrapped_key = base64.b64decode(blob["wrapped_key"])
        nonce = base64.b64decode(blob["nonce"])
        tag = base64.b64decode(blob["tag"])
        ciphertext = base64.b64decode(blob["ciphertext"])
    except Exception as e:
        print("Malformed blob contents:", e)
        return

    # unwrap AES key
    try:
        aes_key = rsa_unwrap_key(wrapped_key, owner_priv)
    except Exception as e:
        log_intrusion(f"Failed unwrap attempt for {enc_filename}: {e}")
        print("[!] Failed to unwrap AES key (possible tampering or wrong key).")
        return

    # decrypt
    try:
        plaintext = aes_decrypt(nonce, ciphertext, tag, aes_key)
    except Exception as e:
        log_intrusion(f"Failed decryption attempt for {enc_filename}: {e}")
        print("[!] Decryption failed (integrity check failed).")
        return

    # write output
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted and wrote file to: {out_path}")

def list_vault():
    files = sorted(os.listdir(VAULT_DIR))
    if not files:
        print("[*] Vault is empty.")
        return
    print("[*] Vault contents:")
    for f in files:
        print(" -", f)

def show_ledger():
    ledger = load_ledger()
    print(json.dumps(ledger, indent=2))

def verify_file(enc_filename: str) -> bool:
    """
    Verify the ledger chain is intact and that the specified blob matches its ledger record.
    """
    if not os.path.exists(LEDGER_FILE):
        print("[!] Ledger does not exist.")
        return False
    ledger = load_ledger()
    # verify chain hashes & signatures
    with open(OWNER_PUB_PATH, "rb") as f:
        owner_pub = f.read()

    prev_hash = ""
    for idx, rec in enumerate(ledger["chain"]):
        rec_copy = rec.copy()
        signature_b64 = rec_copy.pop("signature", None)
        rec_entry_hash = rec_copy.get("entry_hash", None)
        # remove stored entry_hash before recomputing
        if "entry_hash" in rec_copy:
            rec_copy.pop("entry_hash")
        # compute json canonical hash
        entry_json = json.dumps(rec_copy, sort_keys=True).encode()
        recomputed_hash = sha256_bytes(entry_json)
        # verify chain linkage
        if rec_copy.get("prev_hash", "") != prev_hash:
            print(f"[!] Chain break at index {idx}: prev_hash mismatch.")
            return False
        # verify entry hash matches recorded entry_hash
        if rec_entry_hash != recomputed_hash:
            print(f"[!] Entry hash mismatch at index {idx}.")
            return False
        # verify signature
        if signature_b64 is None:
            print(f"[!] Missing signature at index {idx}.")
            return False
        signature = base64.b64decode(signature_b64)
        if not verify_signature(entry_json, signature, owner_pub):
            print(f"[!] Signature verification failed at index {idx}.")
            return False
        prev_hash = rec_entry_hash

    # Now verify specific file blob sha
    enc_full = os.path.join(VAULT_DIR, enc_filename)
    if not os.path.exists(enc_full):
        print("[!] Encrypted file missing from vault.")
        return False
    with open(enc_full, "rb") as f:
        blob_json = f.read()
    try:
        blob = json.loads(blob_json)
    except:
        print("[!] Blob unreadable or corrupted.")
        return False
    blob_hash = sha256_bytes(json.dumps(blob, sort_keys=True).encode())
    # search ledger for file record
    ledger = load_ledger()
    for rec in ledger["chain"]:
        if rec.get("file") == enc_filename:
            if rec.get("blob_sha256") == blob_hash:
                print("[+] File verified: ledger entry matches blob hash and ledger chain is intact.")
                return True
            else:
                print("[!] File hash mismatch vs ledger. Possible tampering.")
                return False
    print("[!] No ledger record found for that file.")
    return False

# ---------- CLI ----------
def print_help():
    print(__doc__)

def main():
    if len(sys.argv) < 2:
        print_help()
        return

    cmd = sys.argv[1].lower()
    if cmd == "init":
        print("[*] Ensure you have run generate_keys.py and created keys/owner_private.pem & keys/owner_public.pem")
    elif cmd == "store" and len(sys.argv) == 3:
        store_file(sys.argv[2])
    elif cmd == "retrieve" and len(sys.argv) == 4:
        retrieve_file(sys.argv[2], sys.argv[3])
    elif cmd == "list":
        list_vault()
    elif cmd == "ledger":
        show_ledger()
    elif cmd == "verify" and len(sys.argv) == 3:
        verify_file(sys.argv[2])
    else:
        print_help()

if __name__ == "__main__":
    main()
