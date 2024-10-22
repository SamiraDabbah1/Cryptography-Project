# Cryptography-Project

# 📧 🔒 Secure Email Exchange: Encryption-Decryption with FEAL in CFB Mode + Secret Key Delivery using Merkle–Hellman Knapsack + EC EL-GAMAL Signature

This application provides secure email exchange by leveraging:

## 🛡️ Encryption-Decryption with FEAL-4 in CFB Mode:
Ensures that your emails are securely encrypted and decrypted using the FEAL-4 algorithm in Cipher Feedback (CFB) mode.

## 🔑 Merkle–Hellman Knapsack Key Exchange:
Implements secure key exchange using the Merkle–Hellman Knapsack, ensuring that your keys are exchanged safely and securely.

## ✍️ Signature with EC ElGamal:
Utilizes Elliptic Curve ElGamal for digital signatures, adding an additional layer of security by verifying the authenticity and integrity of your emails.


## 🧩 Components

- **FEAL-4**: A block cipher designed for lightweight encryption and decryption operations.
- **CFB Mode**: A block cipher mode of operation allowing secure streaming of encrypted data.
- **Merkle–Hellman Knapsack**: A cryptographic scheme for secure key distribution based on the Knapsack problem.
- **Elliptic Curve Cryptography (ECC)**: An approach to public-key cryptography based on the algebraic structure of elliptic curves over finite fields.
- **EC ElGamal Signature Scheme**: A digital signature scheme ensuring message authenticity and integrity based on elliptic curves.

## 🔑 Key Exchange

To resolve key exchange in the symmetric algorithm, we use the Merkle–Hellman Knapsack, a mathematical method for securely exchanging cryptographic keys over a public channel. Alice and Bob attach EC ElGamal signatures to their public keys for verification to prevent tampering.

## 🔐 Encryption

- **Check Key**: The key must be appropriately set for the FEAL-4 algorithm. Ensure it is 64-bit in length.
- **Text Partition**: The text is partitioned into smaller blocks for CFB mode. If the last block is smaller than the required size, padding is applied.
- **CFB Mode**: Loop over the blocks and encrypt each using FEAL-4 with CFB. Concatenate all ciphertext blocks into one string and return.

## 🔓 Decryption

- **Check Key**: Ensure the key is 64-bit.
- **Text Partition**: Partition the text into appropriately sized blocks. Each block is decrypted using FEAL-4 and CFB mode.

## ✍️ Digital Signature

Alice generates a digital signature on her message using EC ElGamal, and Bob verifies it after decryption to ensure message integrity.

## 🔄 Project Flow

Alice and Bob use Merkle–Hellman to exchange keys and compute a shared key. They agree on values, choose private keys, compute public keys, generate and share signatures using EC ElGamal. Alice writes and encrypts a message, then shares ciphertext, IV, and signature with Bob. Bob decrypts the ciphertext and verifies the signature.

## 📊 Conclusions

This application combines FEAL-4 encryption in CFB mode, Merkle–Hellman key exchange, and EC ElGamal signature to ensure secure email communication and data protection, providing robust encryption, decryption, and secure key delivery.
