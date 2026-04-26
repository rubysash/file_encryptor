# GEMINI.md - File Encryptor Tool Context

This document provides foundational context and instructions for the File Encryptor Tool project.

## Project Overview

**File Encryptor Tool v0.05** is a Python-based graphical user interface (GUI) application that allows users to securely encrypt and decrypt files. It uses symmetric encryption (Fernet scheme) powered by the `cryptography` library.

### Key Technologies
- **Language:** Python 3.x
- **GUI Framework:** `tkinter`
- **Encryption:** `cryptography.fernet` (AES-128 in CBC mode)
- **Data Storage:** JSON (for encrypted file metadata)
- **Hashing:** MD5 (for file integrity verification), SHA-256 (for key derivation)

### Architecture
The project is primarily contained within `main.py`, which handles both the GUI logic and the cryptographic operations.
- **Encryption Flow:** User Password -> SHA-256 Hash -> URL-safe Base64 Encoding -> Fernet Key.
- **File Processing:** Files are Base64 encoded before being encrypted to ensure compatibility and integrity.
- **Output:** Encrypted files are saved as JSON objects containing the encrypted filename, the encrypted MD5 hash of the original file, and the encrypted file data.

## Building and Running

### Prerequisites
- Python 3.x
- A virtual environment is recommended (already set up in this workspace in `Lib/`, `Scripts/`, `Include/`).

### Setup and Execution

#### Windows
1.  **Activate Environment:** `.\Scripts\activate`
2.  **Install Dependencies:** `pip install -r requirements.txt`
3.  **Run Application:** `python main.py` or use the provided `start.bat`.

#### macOS / Linux
1.  **Activate Environment:** `source bin/activate`
2.  **Install Dependencies:** `pip install -r requirements.txt`
3.  **Run Application:** `python3 main.py`

## Development Conventions

- **Password Security:** The application enforces a strong password policy (minimum 14 characters, including uppercase, lowercase, digits, and symbols).
- **Integrity Checks:** MD5 hashes are used to verify that decrypted files match the original source.
- **GUI Style:** Uses `tkinter.ttk` with the 'clam' theme for a consistent look.
- **Code Documentation:** `main.py` contains extensive docstrings explaining the encryption logic and brute-force complexity.

## Known Limitations and Future Improvements (TODOs)
- **Salting:** The current implementation derives the encryption key directly from the SHA-256 hash of the password without a unique salt. Adding a salt (e.g., using Scrypt or Argon2) is a recommended security refactor.
- **Symmetric Nature:** Both encryption and decryption require the same password/key.
- **Metadata Exposure:** While the file content and name are encrypted, the fact that a file is an "encrypted JSON" is visible by its structure.
