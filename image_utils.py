"""
Image Handlers for StegoSecure.
Functions to read, save images, check capacity, and strip metadata for privacy.
"""
from PIL import Image
import hashlib

def load_image(image_path: str) -> Image.Image:
    """Loads an image and ensures it is in RGB mode."""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    return img

def save_image(img: Image.Image, output_path: str):
    """
    Saves the image. Strips EXIF metadata by default in PIL when saving
    unless explicitly passed. We omit EXIF to enhance privacy and reduce detectability.
    """
    img.save(output_path, format="PNG")

def get_image_capacity_bits(img: Image.Image) -> int:
    """
    Calculates maximum hiding capacity in bits.
    We use 1 LSB per color channel (R, G, B), so 3 bits per pixel.
    """
    width, height = img.size
    total_pixels = width * height
    # 3 channels (RGB) * 1 LSB per channel
    return total_pixels * 3

def compute_image_hash(image_path: str) -> str:
    """Computes SHA-256 hash of an image file for integrity verification."""
    hasher = hashlib.sha256()
    with open(image_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()
