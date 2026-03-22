"""
Custom logger implementation for StegoSecure.
Ensures all security-relevant events (successful decoding, failed access, errors) are logged.
"""

import logging
import os
from config import LOG_DIR

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def get_logger(name):
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers if logger is imported multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)

        # Create file handler
        log_file = os.path.join(LOG_DIR, 'stegosecure.log')
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)

        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # Add handlers
        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger

# Main project logger
main_logger = get_logger("StegoSecure")
