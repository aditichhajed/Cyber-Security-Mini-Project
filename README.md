# 🔐 SecureBox — Cybersecurity Mini Project

## 📘 Overview

**SecureBox** is a Python-based cybersecurity mini project that demonstrates secure file storage using hybrid encryption (RSA + AES), digital signatures, hash-chain integrity verification, and intrusion detection.

It provides end-to-end protection for files — ensuring **Confidentiality, Integrity, Authentication, and Non-repudiation**.

---

## ⚙️ Features

- **AES-256 encryption** for fast, secure file storage
- **RSA-2048** for key protection and digital signatures
- **Tamper-evident ledger** (hash chain similar to blockchain)
- **Intrusion log** and live monitoring of suspicious activity
- **CLI interface** for storing, verifying, and retrieving files

---

## 🧩 Folder Structure

```
SecureBox/
│
├── generate_keys.py          # Generates RSA key pairs
├── crypto_utils.py            # AES/RSA encryption, signing, hashing
├── securebox.py               # Main CLI tool (store / verify / retrieve)
├── intrusion_monitor.py       # Monitors intrusion.log for suspicious activity
├── ledger.json                # Tamper-evident ledger (auto-updated)
├── vault/                     # Stores encrypted files
└── keys/                      # RSA keys generated here
```

---

## 🛠️ Setup

### 1. Install dependencies

```bash
pip install pycryptodome colorama
```

### 2. Generate RSA keys

```bash
python generate_keys.py
```

**Creates:**

```
keys/
├── owner_private.pem
├── owner_public.pem
├── share_private.pem
└── share_public.pem
```

---

## 🚀 Usage

### Encrypt & Store a File

```bash
python securebox.py store test.txt
```

**Output:**

```
[+] Stored encrypted file: vault/test.txt.enc
[+] Ledger updated.
```

### List Stored Files

```bash
python securebox.py list
```

### Verify File Integrity

```bash
python securebox.py verify test.txt.enc
```

### Retrieve (Decrypt) a File

```bash
python securebox.py retrieve test.txt.enc recovered_test.txt
```

### View Ledger

```bash
python securebox.py ledger
```

### Run Intrusion Monitor

```bash
python intrusion_monitor.py
```

---

## 🔒 Security Layers

| Layer          | Technique          | Purpose                 |
| -------------- | ------------------ | ----------------------- |
| Encryption     | AES-256            | Confidentiality         |
| Key Wrapping   | RSA-2048           | Secure AES key exchange |
| Integrity      | SHA-256 Hash Chain | Detect tampering        |
| Authentication | RSA-PSS Signature  | Verify authenticity     |
| Detection      | Log & Monitor      | Identify intrusions     |

---

## 🧠 Concepts Covered

- Symmetric & Asymmetric Encryption
- Hashing and Digital Signatures
- Hybrid Cryptography
- Intrusion Detection & Logging
- CIA Triad (Confidentiality, Integrity, Availability)

---

## 📚 Requirements

- **Python 3.8+**
- **Libraries:** `pycryptodome`, `colorama`

---

## 👩‍💻 Author

**Aditi Chhajed**  
B.Tech Computer Science — Cyber Security Mini Project  
VJTI College

---

## 🏁 Summary

SecureBox integrates encryption, integrity verification, and intrusion detection into one cohesive system.

It demonstrates how multiple cybersecurity layers work together to protect digital assets and provides a practical foundation for secure data management.

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- Python Cryptography Community
- VJTI College Faculty
- Open Source Security Tools

---

<div align="center">

**⭐ If you found this project helpful, please give it a star! ⭐**

Made with ❤️ for Cybersecurity Education

</div>
