"""
Cryptographic Utilities for StegoSecure.
Handles encryption (AES-GCM), key derivation (PBKDF2), compression (zlib), 
and integrity verification (SHA-256).
"""
import os
import zlib
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from config import SALT_SIZE, NONCE_SIZE, TAG_SIZE, KDF_ITERATIONS, KEY_SIZE
from logger import main_logger

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure cryptographic key from a password.
    Why: Never use a raw password directly. PBKDF2 slows down brute-force attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_SIZE)

def generate_nonce() -> bytes:
    """Generates a cryptographically secure random nonce (IV) for AES-GCM."""
    return os.urandom(NONCE_SIZE)

def generate_hash(data: bytes) -> bytes:
    """
    Computes SHA-256 hash of the given data.
    Why: Ensures the plaintext integrity during decoding.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def build_secure_payload(message: str, password: str) -> bytes:
    """
    Prepares the final binary payload for embedding:
    1. Compress plaintext
    2. Hash compressed plaintext
    3. Encrypt (Hash + Compressed_Plaintext) with AES-GCM
    4. Prepend Salt, Nonce, Tag
    """
    try:
        # Step 1: Compress message
        compressed_msg = zlib.compress(message.encode('utf-8'))
        
        # Step 2: Generate Integrity Hash
        msg_hash = generate_hash(compressed_msg)
        
        # Payload to encrypt = Hash (32 bytes) + Compressed message
        data_to_encrypt = msg_hash + compressed_msg
        
        # Step 3: Crypto Setup
        salt = generate_salt()
        nonce = generate_nonce()
        key = derive_key(password, salt)
        
        # Step 4: Encrypt using AES-GCM (Provides Confidentiality + Authenticity)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, associated_data=None)
        
        # In cryptography's AESGCM, the authentication tag is appended to the ciphertext
        # We will split it to maintain our structural pattern
        actual_ciphertext = ciphertext[:-16]
        tag = ciphertext[-16:]
        
        # Total payload = [Salt(16)] [Nonce(12)] [Tag(16)] [Ciphertext(var size)]
        payload = salt + nonce + tag + actual_ciphertext
        main_logger.info("Successfully built secure payload.")
        return payload
    except Exception as e:
        main_logger.error(f"Error building secure payload: {str(e)}")
        raise

def parse_secure_payload(payload: bytes, password: str) -> str:
    """
    Reverses the process:
    1. Extracts Salt, Nonce, Tag, Ciphertext
    2. Derives Key and Decrypts (AES-GCM verifies Tag)
    3. Separates Hash from Compressed message
    4. Verifies Integrity Hash
    5. Decompresses to original string
    """
    try:
        # Step 1: Extract components based on constants
        if len(payload) < (SALT_SIZE + NONCE_SIZE + TAG_SIZE + 32): # at least hash length inside ciphertext
            raise ValueError("Payload too small to contain valid secure data.")
            
        salt = payload[:SALT_SIZE]
        nonce = payload[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        tag = payload[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+TAG_SIZE]
        actual_ciphertext = payload[SALT_SIZE+NONCE_SIZE+TAG_SIZE:]
        
        # Recombine tag for cryptography library
        cryptography_ciphertext = actual_ciphertext + tag
        
        # Step 2: Derive Key
        key = derive_key(password, salt)
        
        # Step 3: Decrypt (This will raise InvalidTag if wrong password or tampered)
        aesgcm = AESGCM(key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, cryptography_ciphertext, associated_data=None)
        except InvalidTag:
            main_logger.warning("Decryption failed. Incorrect password or tampered data.")
            raise ValueError("Authentication failed. Incorrect password or data corrupted.")
            
        # Step 4: Extract Hash and verify
        extracted_hash = decrypted_data[:32]
        compressed_msg = decrypted_data[32:]
        
        recomputed_hash = generate_hash(compressed_msg)
        if extracted_hash != recomputed_hash:
            main_logger.warning("Integrity check failed. Hash mismatch.")
            raise ValueError("Data integrity compromised. Hashes do not match.")
            
        # Step 5: Decompress
        original_msg = zlib.decompress(compressed_msg).decode('utf-8')
        main_logger.info("Successfully parsed and decrypted secure payload.")
        return original_msg
        
    except Exception as e:
        main_logger.error(f"Payload parsing error: {str(e)}")
        raise
