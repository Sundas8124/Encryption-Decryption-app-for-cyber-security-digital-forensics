# Encryption-Decryption-app-for-cyber-security-digital-forensics
This app will help you to encrypt or decrypt a text using different ciphers and secret keys. This code is just for educational purpose and is not as such safe for well developed level but highly acceptable for university level projects.
Encryption & Decryption Tool
A simple GUI-based Python application for encrypting and decrypting text using Base64, DES, and AES ciphers. The tool requires an encryption key for DES and AES and provides a user-friendly interface built with tkinter.

Features
Encrypt and decrypt any text using:
Base64 (no key required)
DES (key must be 8 bytes)
AES (key must be 16 bytes)
Masked input for encryption key
Simple copy-to-clipboard functionality for output
Clean and user-friendly GUI interface
Requirements
Python 3.x
Dependencies:
pycryptodome (for AES and DES)
Install dependencies with:

pip install pycryptodome
Usage
Run the script with:

python encryptanddecrypt.py
Interface Walkthrough
Enter Text – Input the text you wish to encrypt or decrypt.
Enter Encryption Key – Input the key (Required for DES and AES).
Select Cipher – Choose between Base64, DES, or AES.
Encrypt/Decrypt Buttons – Perform the desired operation.
Output – Displays the encrypted or decrypted result.
Copy to Clipboard – Copies the output to your clipboard.
Notes
Base64 does not require a key and is not secure for sensitive data.
DES requires an 8-byte key (extra characters will be trimmed, and shorter keys padded).
AES requires a 16-byte key (same behavior as DES).
Currently uses ECB mode, which is not secure for production applications.
Security Warning
This tool is intended for educational and basic utility purposes. ECB mode is not recommended for secure applications. Always use secure key management and modern cipher modes (e.g., CBC, GCM) in production environments.

License
MIT License
