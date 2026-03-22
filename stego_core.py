"""
Core Steganography Engine for StegoSecure.
Implements Key-Based PRNG for pixel selection and LSB embedding/extraction.
"""
import random
from PIL import Image
from crypto_utils import generate_hash, build_secure_payload, parse_secure_payload
from image_utils import load_image, save_image, get_image_capacity_bits
from logger import main_logger

def get_embedding_sequence(password: str, total_channels: int) -> list:
    """
    Generates a secure pseudo-random sequence of unique indices using a password-derived seed.
    Why: By scattering embedded bits randomly across the image, we defeat simple 
    sequential steganalysis tools and ensure only someone with the key knows WHERE the data is.
    """
    # Seed PRNG with the hash of the password
    seed_int = int.from_bytes(generate_hash(password.encode('utf-8')), byteorder='big')
    rand = random.Random(seed_int)
    
    indices = list(range(total_channels))
    rand.shuffle(indices)
    return indices

def encode_message(image_path: str, message: str, password: str, output_path: str):
    """
    Encodes a secret message into an image.
    """
    main_logger.info(f"Starting encoding process for {image_path}")
    img = load_image(image_path)
    
    payload = build_secure_payload(message, password)
    
    # 4 bytes for length
    payload_length = len(payload)
    payload_length_bytes = payload_length.to_bytes(4, byteorder='big')
    full_payload = payload_length_bytes + payload
    
    # Convert payload to bit string
    bit_array = ''.join([f"{byte:08b}" for byte in full_payload])
    num_bits = len(bit_array)
    
    max_capacity = get_image_capacity_bits(img)
    if num_bits > max_capacity:
        main_logger.error(f"Insufficient capacity. Required: {num_bits} bits, Available: {max_capacity} bits.")
        raise ValueError("Image is too small to hold this encrypted message.")
        
    pixels = list(img.getdata())
    total_channels = len(pixels) * 3
    
    indices = get_embedding_sequence(password, total_channels)
    
    # Create mutable copy of pixels
    mutable_pixels = [list(p) for p in pixels]
    
    for i, bit in enumerate(bit_array):
        idx = indices[i]
        pixel_idx = idx // 3
        channel_idx = idx % 3
        
        # Modify the LSB
        val = mutable_pixels[pixel_idx][channel_idx]
        val = (val & ~1) | int(bit)
        mutable_pixels[pixel_idx][channel_idx] = val
        
    # Rebuild image
    final_pixels = [tuple(p) for p in mutable_pixels]
    img.putdata(final_pixels)
    
    save_image(img, output_path)
    main_logger.info(f"Encoding successful. Stego image saved to {output_path}")

def decode_message(image_path: str, password: str) -> str:
    """
    Decodes a secret message from an image.
    """
    main_logger.info(f"Starting decoding process for {image_path}")
    img = load_image(image_path)
    pixels = list(img.getdata())
    total_channels = len(pixels) * 3
    
    indices = get_embedding_sequence(password, total_channels)
    
    def extract_bits(n_bits, start_offset_in_indices):
        bits = []
        for i in range(n_bits):
            idx = indices[start_offset_in_indices + i]
            pixel_idx = idx // 3
            channel_idx = idx % 3
            val = pixels[pixel_idx][channel_idx]
            bits.append(str(val & 1))
        return ''.join(bits)
        
    # 1. Extract Length
    length_bits = extract_bits(32, 0)
    payload_length = int(length_bits, 2)
    
    # Validate obvious false lengths to prevent memory errors
    if payload_length <= 0 or payload_length > (total_channels // 8):
        main_logger.warning("Decoded length is nonsensical. Possibly a wrong password or non-stego image.")
        raise ValueError("Invalid decoded length. Wrong password or image corrupted.")
        
    # 2. Extract full payload bytes
    total_payload_bits = payload_length * 8
    payload_bits_str = extract_bits(total_payload_bits, 32)
    
    payload_bytes = bytearray()
    for i in range(0, len(payload_bits_str), 8):
        byte_val = int(payload_bits_str[i:i+8], 2)
        payload_bytes.append(byte_val)
        
    # 3. Parse secure payload to get plaintext
    message = parse_secure_payload(bytes(payload_bytes), password)
    
    main_logger.info("Decoding successful. Message recovered and verified.")
    return message
