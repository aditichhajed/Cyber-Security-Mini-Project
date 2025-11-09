#!/usr/bin/env python3
"""
crypto_utils.py
Utility functions for hybrid encryption, signing, and hashing used by SecureBox.

Features:
- AES-256-GCM encryption/decryption of file bytes
- RSA wrap/unwrap of AES session keys (PKCS1_OAEP)
- RSA-PSS signing and verification of ledger entries
- SHA256 hashing for integrity and ledger chaining
"""
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from typing import Tuple

# AES key size in bytes (32 => AES-256)
AES_KEY_BYTES = 32
NONCE_BYTES = 12  # recommended for GCM

# ---------- AES (GCM) ----------
def aes_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt bytes with AES-GCM.
    Returns tuple(nonce, ciphertext, tag).
    """
    nonce = get_random_bytes(NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def aes_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM bytes. Raises ValueError if verification fails.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# ---------- RSA wrap/unwrap (PKCS1_OAEP) ----------
def rsa_wrap_key(aes_key: bytes, rsa_pub_pem: bytes) -> bytes:
    """
    Encrypt (wrap) an AES session key with an RSA public key (PEM bytes).
    """
    rsa_pub = RSA.import_key(rsa_pub_pem)
    cipher = PKCS1_OAEP.new(rsa_pub)
    return cipher.encrypt(aes_key)

def rsa_unwrap_key(enc_key: bytes, rsa_priv_pem: bytes) -> bytes:
    """
    Decrypt (unwrap) an AES session key with an RSA private key (PEM bytes).
    """
    rsa_priv = RSA.import_key(rsa_priv_pem)
    cipher = PKCS1_OAEP.new(rsa_priv)
    return cipher.decrypt(enc_key)

# ---------- RSA signing / verification (PSS + SHA256) ----------
def sign_bytes(data: bytes, rsa_priv_pem: bytes) -> bytes:
    """
    Sign data using RSA-PSS and SHA256. Returns signature bytes.
    """
    rsa_priv = RSA.import_key(rsa_priv_pem)
    h = SHA256.new(data)
    signer = pss.new(rsa_priv)
    return signer.sign(h)

def verify_signature(data: bytes, signature: bytes, rsa_pub_pem: bytes) -> bool:
    """
    Verify RSA-PSS signature. Returns True if valid, False otherwise.
    """
    rsa_pub = RSA.import_key(rsa_pub_pem)
    h = SHA256.new(data)
    verifier = pss.new(rsa_pub)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---------- Hashing ----------
def sha256_bytes(data: bytes) -> str:
    """
    Return hex digest of SHA256 for provided bytes.
    """
    h = SHA256.new(data)
    return h.hexdigest()

# ---------- Helpers ----------
def generate_aes_key() -> bytes:
    return get_random_bytes(AES_KEY_BYTES)
