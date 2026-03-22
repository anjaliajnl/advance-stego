# StegoSecure – Advanced Steganography Secure Messaging System

## Project Overview
**StegoSecure** is a production-level, cybersecurity-focused steganography tool. It goes far beyond the basic LSB (Least Significant Bit) algorithms taught in traditional tutorials by layering authenticated encryption, secure key derivation, cryptographic hashing, and randomized pixel embedding to provide a resilient, secure communication channel.

## Problem Statement
Basic LSB steganography has major limitations:
- **No Encryption**: Anyone who discovers the hiding technique can read the message.
- **Vulnerability to Compresssion**: Lossy formats like JPEG destroy hidden LSBs.
- **High Detectability**: Attackers can easily analyze sequential pixel changes.
- **Lack of Authentication & Integrity**: There is no way to verify who sent the message or if it was tampered with in transit.

## Improvements Added
StegoSecure rectifies these flaws with a defense-in-depth approach:
1. **Pre-Compression (zlib)**: Minimizes payload size, effectively increasing image capacity and slightly masking patterns.
2. **Key Derivation (PBKDF2-HMAC-SHA256)**: Slows down brute-force attacks against user passwords.
3. **Authenticated Encryption (AES-GCM)**: Protects the confidentiality of the data and provides cryptographic authentication to catch tampering.
4. **Integrity Verification (SHA-256)**: The original plaintext is hashed, and this hash is verified post-decryption.
5. **Key-Based Random Embedding (PRNG)**: Bits are scattered pseudo-randomly across image channels using a password-derived seed, significantly hardening the payload against simple steganalysis tools.
6. **Brute-Force Protection**: The system limits consecutive failed decoding attempts and utilizes desktop notifications for alerts.

## Project Architecture
1. **app.py**: Provides the Streamlit Web-based User Interface.
2. **stego_core.py**: Manages PRNG sequences and spatial domain bit substitutions.
3. **crypto_utils.py**: Handles PBKDF2 key derivation, AES encryption, SHA-256, and payload structural packing.
4. **image_utils.py**: Oversees capacity detection, image integrity verification, and metadata removal.
5. **security_manager.py**: Implements the rate limiting and plyer-based notifications.
6. **jpeg_stego.py**: Designed as an extensible stub demonstrating why JPEG LSB fails and defining future DCT integration.

## Workflow

### Encoding
1. Read target image and plaintext message.
2. Compress plaintext message using zlib.
3. Compute SHA-256 hash of plaintext for integrity checking.
4. Generate a random Salt and 12-byte Nonce. Derive AES Key from user Password and Salt using PBKDF2 (480k rounds).
5. Encrypt [Hash + Compressed Plaintext] using AES-GCM, producing Cipherext and an Authentication Tag.
6. Construct Payload: `Length | Salt | Nonce | Tag | Ciphertext`.
7. Extract pixels, compute capacity.
8. Seed a PRNG with a derivation of the password. Generate a scattered sequence of indices.
9. Iteratively embed the payload bitwise into the LSBs corresponding to the PRNG sequence.
10. Save the modified image.

### Decoding
1. Read the stego image.
2. Re-create the identical PRNG sequence using the generated seed from the password.
3. Extract the first 32 bits from the scatter sequence to deduce the Payload Length.
4. Extract the remaining payload bits based on length.
5. Parse the extracted block into: `Salt`, `Nonce`, `Tag`, and `Ciphertext`.
6. Derive AES key via PBKDF2 using the pulled Salt and User Password.
7. Attempt decryption utilizing AES-GCM with the `Tag`. If the wrong password or wrong tag is used, AES-GCM raises an exception instantly.
8. Extract the `Hash` and `Compressed Plaintext` from the decrypted data.
9. Verify the Hash matches the data precisely.
10. Decompress using zlib to reveal the message.

## Usage
### Prerequisites
```bash
pip install -r requirements.txt
```

### Running the GUI
```bash
streamlit run app.py
```

## Future Scope
- **Full DCT Implementation**: Implement actual DCT zero-coefficient embedding for robust JPEG support.
- **Adaptive Steganography**: Embed heavily in complex (noisy) image regions and spare the smooth areas (sky, plain walls).
- **Error Correction Coding**: Utilize Hamming codes or Reed-Solomon to allow data recovery even if slight image mutations occur over transmission.
