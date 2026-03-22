"""
Configuration parameters for StegoSecure.
Centralizes constants used across the system for easy tweaking.
"""

import os

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# Crypto parameters
SALT_SIZE = 16  # 16 bytes for secure salt
NONCE_SIZE = 12 # 12 bytes standard IV for AES-GCM
TAG_SIZE = 16   # 16 bytes authentication tag for AES-GCM
KDF_ITERATIONS = 480000  # High iteration count for PBKDF2 to thwart brute-forcing
KEY_SIZE = 32  # 32 bytes (256-bit) AES key

# Steganography parameters
# Payload layout: Length (4) | Salt (16) | Nonce (12) | Tag (16) | Ciphertext
METADATA_LENGTH_BYTES = 4
HEADER_OVERHEAD = METADATA_LENGTH_BYTES + SALT_SIZE + NONCE_SIZE + TAG_SIZE

# Brute force protection
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME_SECONDS = 30
