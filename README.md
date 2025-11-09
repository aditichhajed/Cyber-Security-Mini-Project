# 🔐 SecureBox — A Local File Encryption, Integrity & Intrusion Detection System

## 📘 Project Overview

**SecureBox** is a Python-based mini cybersecurity project that securely stores, verifies, and protects sensitive files using a combination of **cryptography**, **integrity validation**, and **intrusion detection**.

It demonstrates **Confidentiality**, **Integrity**, **Authentication**, and **Non-repudiation** — the core principles of information security — through real cryptographic mechanisms and secure logging.

This system acts like a **mini encrypted vault**, combining encryption, digital signatures, and tamper-evident logs (a lightweight blockchain ledger).

---

## 🎯 Objectives

- To develop a **secure local file vault** using hybrid cryptography (RSA + AES)
- To ensure **data confidentiality** through strong encryption
- To maintain **file integrity and authenticity** using digital signatures and hash chaining
- To detect **unauthorized access attempts** via intrusion monitoring
- To provide a real-world demonstration of **CIA triad** and **security auditing**

---

## 🧠 Key Concepts Demonstrated

| Security Principle      | Implementation                                    |
| ----------------------- | ------------------------------------------------- |
| **Confidentiality**     | AES-256 (symmetric encryption)                    |
| **Integrity**           | SHA256 hash chain ledger (like a mini blockchain) |
| **Authentication**      | RSA key pair verification                         |
| **Non-Repudiation**     | Digital signatures (RSA-PSS)                      |
| **Intrusion Detection** | Log monitoring via `intrusion_monitor.py`         |
| **Security Auditing**   | Immutable ledger entries for all file actions     |

---

## 🏗️ System Architecture

      +----------------+
      |  User Input    |
      +--------+-------+
               |
               v
      +--------+--------+
      |  SecureBox CLI  |  ← main controller
      +--------+--------+
               |

+-----------+------------+
| |
v v
+--------------+ +------------------+
| crypto_utils | | intrusion_monitor|
| (AES + RSA + | | (log watcher & |
| signature) | | alert generator)|
+--------------+ +------------------+
|
v
+--------------------------+
| vault/ (encrypted files) |
+--------------------------+
|
v
+--------------------------+
| ledger.json (tamper log) |
+--------------------------+

---

## ⚙️ Folder Structure

SecureBox/
│
├── generate_keys.py # Generates RSA key pairs
├── crypto_utils.py # Encryption, decryption, signing, hashing utilities
├── securebox.py # Main CLI tool for storage, retrieval, and verification
├── intrusion_monitor.py # Monitors failed access attempts and raises alerts
├── ledger.json # Tamper-evident ledger for stored files
├── vault/ # Stores encrypted files
└── keys/ # Contains generated RSA key pairs

---

## 🧰 Tech Stack

- **Language:** Python 3.x
- **Libraries Used:**
  - `pycryptodome` — Cryptography (AES, RSA, Hashing, Signing)
  - `colorama` — Console text coloring
  - `json` — Ledger serialization
  - `socket`, `os`, `datetime` — System utilities

Install dependencies:

```bash
pip install pycryptodome colorama
```
