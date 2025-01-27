## Secure File Encryption System
## Overview
This Python project provides a robust file encryption and decryption system using AES encryption with support for ECB and CBC modes.
# Features:
- AES encryption for files
- Support for ECB and CBC encryption modes
- Flexible key and IV handling
- File integrity verification
- Secure padding implementation
# Prerequisites
- Python 3.7+
- cryptography library
-PyQt5 library
## Usage
1.	Using the GUI which is easy to use for most of the users.
 
2.	Basic Encryption:
# Initialize encryptor with key and IV
encryptor = FileEncryptor(key=b'MySecretKey123', iv=b'RandomInitVector')
 
# Encrypt file in CBC mode
encryptor.encrypt_file('input.txt', 'encrypted.bin', mode='cbc')
 
# Decrypt file
encryptor.decrypt_file('encrypted.bin', 'decrypted.txt', mode='cbc'
check out “test” folder
3.	Verify file integrity:
is_intact = FileEncryptor.verify_file_integrity('input.txt', 'decrypted.txt')

# Security Considerations:
- Use strong, unique keys and initialization vectors
- Avoid ECB mode for sensitive data
- Protect your encryption keys
Modes of Operation:
- ECB (Electronic Codebook): Simple but less secure
- CBC (Cipher Block Chaining): More secure, recommended for most use cases
Error Handling:
- Raises `ValueError` for unsupported encryption modes
- Supports automatic key and IV processing
