# Cryptographic Security Toolkit

A Python toolkit demonstrating file integrity verification and secure user authentication using cryptographic techniques. This repository contains two main projects showcasing practical implementations of cryptographic security concepts.

## Projects

### 1. File_integrity_checker
**File:** `File_integrity_checker.py`

A Python tool for verifying file integrity using multiple cryptographic hash algorithms. Detects file tampering by comparing original and modified hash values.

#### Features
- **Multiple Hash Algorithms:** MD5, SHA-1, SHA-256, SHA-3 (Keccak)
- **Integrity Verification:** Compares original vs modified file hashes
- **Tamper Detection:** Automatically detects file modifications
- **Hash Storage:** Saves hash values to text files for future verification

#### Usage
```bash
python File_integrity_checker.py
```

The program will:
1. Ask for a file path
2. Calculate and save original hashes
3. Simulate file tampering
4. Compare hashes to detect changes
5. Optionally save modified hashes

---

### 2. Secure_authentication_system
**File:** `Secure_authentication_system.py`

A comprehensive user authentication system implementing secure password storage with salted hashing, AES encryption, and elliptic curve digital signatures.

#### Features
- **Secure Password Storage:** Salted MD5 hashing
- **AES Encryption:** 256-bit AES-OFB mode for data encryption
- **Digital Signatures:** ECDSA with SECP256R1 curve
- **User Management:** Create new users and authenticate existing ones
- **File Integrity:** Signature verification for encrypted password files

#### Security Components
- **Salt Generation:** Random 16-byte salt for each password
- **Symmetric Encryption:** AES-256 in OFB mode
- **Asymmetric Signatures:** Elliptic Curve Digital Signature Algorithm (ECDSA)
- **Key Management:** Secure storage of encryption keys and signatures

#### Usage
```bash
python Secure_authentication_system.py
```

The program provides a menu with options to:
1. **Login** - Authenticate existing user
2. **Create User** - Register new user with secure password storage
3. **Exit** - Close the application

## Requirements

### Dependencies
```bash
pip install cryptography
```

### Built-in Libraries Used
- `hashlib` - Cryptographic hash functions
- `os` - Operating system interface
- `base64` - Base64 encoding/decoding

## File Structure

```
cryptographic-security-toolkit/
├── File_integrity_checker.py           # File integrity checker
├── Secure_authentication_system.py     # Secure authentication system
├── README.md                           # This file
└── generated_files/                    # Created during execution
    ├── original_hashes.txt             # Original file hashes
    ├── modified_hashes.txt             # Modified file hashes
    ├── [username].enc                  # Encrypted user data
    ├── [username]_key.key              # AES encryption key
    ├── [username]_signature.sig        # Digital signature
    └── [username]_private_key.pem      # ECDSA private key
```

## Security Notes

### File_integrity_checker
- **Hash Algorithms:** Uses multiple algorithms for comprehensive verification
- **Tamper Detection:** Any modification to the file will change all hash values
- **Collision Resistance:** SHA-256 and SHA-3 provide strong collision resistance

### Secure_authentication_system
- **Password Security:** Passwords are salted and hashed before storage
- **Encryption:** All sensitive data is encrypted with AES-256
- **Digital Signatures:** ECDSA ensures data integrity and authenticity
- **Key Management:** Private keys and encryption keys are stored securely

## Educational Purpose

This toolkit is designed for educational purposes to demonstrate:
- **Cryptographic Hash Functions** and their applications
- **Symmetric Encryption** with AES
- **Asymmetric Cryptography** with elliptic curves
- **Digital Signatures** for authentication
- **Security Best Practices** in password management

## Warning

⚠️ **This code is for educational purposes only.** For production use, consider:
- Using stronger password hashing algorithms (bcrypt, scrypt, Argon2)
- Implementing proper key derivation functions
- Adding comprehensive error handling
- Following security best practices for production environments

## License

This project is intended for educational use. Please ensure compliance with your institution's academic policies when using this code.

---

