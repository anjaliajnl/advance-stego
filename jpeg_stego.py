"""
JPEG / DCT Steganography Module for StegoSecure.
Uses 8x8 block 2D Discrete Cosine Transform (DCT) to embed data in the frequency domain.
Robust against certain spatial lossy degradations compared to LSB spatial stego.
"""
import cv2
import numpy as np
from crypto_utils import build_secure_payload, parse_secure_payload
from logger import main_logger

def is_jpeg(image_path: str) -> bool:
    """Checks if the image is a JPEG."""
    return image_path.lower().endswith(('.jpg', '.jpeg'))

def _get_capacity_bits(img_shape):
    """
    Capacity in bits. We embed 1 bit per 8x8 block in one channel (Y channel).
    """
    rows, cols = img_shape[:2]
    # Number of 8x8 blocks
    return (rows // 8) * (cols // 8)

def encode_jpeg(image_path: str, message: str, password: str, output_path: str):
    """
    DCT-based encoding.
    Loads the image, converts to YCrCb.
    In the Y channel, performs 8x8 DCT, embeds bits in a mid-frequency coefficient,
    performs IDCT, and saves the image.
    To preserve exactly the frequency alterations and prevent re-quantization 
    from destroying data, the output is saved as a lossless PNG, 
    satisfying the requirement of frequency-domain embedding.
    """
    main_logger.info(f"Starting DCT encoding for {image_path}")
    
    # 1. Build Payload
    payload = build_secure_payload(message, password)
    
    # 4 bytes for length
    payload_length = len(payload)
    payload_length_bytes = payload_length.to_bytes(4, byteorder='big')
    full_payload = payload_length_bytes + payload
    
    bit_array = ''.join([f"{byte:08b}" for byte in full_payload])
    num_bits = len(bit_array)
    
    # 2. Load Image and Transform
    # Read via OpenCV
    img = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read image for JPEG encoding.")
        
    # Crop to multiples of 8
    rows, cols = img.shape[:2]
    rows = rows - (rows % 8)
    cols = cols - (cols % 8)
    img = img[:rows, :cols]
    
    max_capacity = _get_capacity_bits(img.shape)
    if num_bits > max_capacity:
         main_logger.error(f"Insufficient capacity in DCT blocks. Required: {num_bits}, Available blocks: {max_capacity}")
         raise ValueError(f"Image too small for DCT stego. Need {num_bits} blocks, have {max_capacity}.")
         
    # Convert BGR to YCrCb
    img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    
    Y = img_ycrcb[:,:,0].astype(np.float32)
    # The quantizer / QIM step size. Larger = more robust, but more visible distortion.
    Q = 30.0  
    
    bit_index = 0
    # Embedding in a mid-frequency AC coefficient
    u, v = 4, 4
    
    for row in range(0, rows, 8):
        for col in range(0, cols, 8):
            if bit_index >= num_bits:
                break
                
            block = Y[row:row+8, col:col+8]
            dct_block = cv2.dct(block)
            
            # Embed bit using Quantization Index Modulation (QIM)
            coeff = dct_block[u, v]
            bit = int(bit_array[bit_index])
            
            quantized = round(coeff / Q)
            remainder = int(abs(quantized)) % 2
            
            if bit == 0:
                if remainder != 0:
                    dct_block[u, v] = (quantized + 1) * Q if (coeff > quantized * Q) else (quantized - 1) * Q
                else:
                    dct_block[u, v] = quantized * Q
            else:
                if remainder != 1:
                    dct_block[u, v] = (quantized + 1) * Q if (coeff > quantized * Q) else (quantized - 1) * Q
                else:
                    dct_block[u, v] = quantized * Q
                    
            # IDCT
            inv_block = cv2.idct(dct_block)
            Y[row:row+8, col:col+8] = inv_block
            
            bit_index += 1
            
    img_ycrcb[:,:,0] = np.clip(Y, 0, 255).astype(np.uint8)
    img_bgr = cv2.cvtColor(img_ycrcb, cv2.COLOR_YCrCb2BGR)
    
    # Save as PNG to avoid destructive secondary quantizations from simple imwrite('.jpg')
    cv2.imwrite(output_path, img_bgr)
    main_logger.info(f"DCT encoding successful. Saved to {output_path}")

def decode_jpeg(image_path: str, password: str) -> str:
    """
    DCT-based decoding.
    """
    main_logger.info(f"Starting DCT decoding for {image_path}")
    
    img = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read image for JPEG decoding.")
        
    rows, cols = img.shape[:2]
    rows = rows - (rows % 8)
    cols = cols - (cols % 8)
    img = img[:rows, :cols]
    
    img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    Y = img_ycrcb[:,:,0].astype(np.float32)
    
    Q = 30.0
    u, v = 4, 4
    
    max_capacity = _get_capacity_bits(img.shape)
    
    def extract_bits(n_bits, start_block_idx):
        bits = []
        block_idx = 0
        for row in range(0, rows, 8):
            for col in range(0, cols, 8):
                if len(bits) >= n_bits:
                    return ''.join(bits)
                    
                if block_idx >= start_block_idx:
                    block = Y[row:row+8, col:col+8]
                    dct_block = cv2.dct(block)
                    coeff = dct_block[u, v]
                    
                    quantized = round(coeff / Q)
                    remainder = int(abs(quantized)) % 2
                    bits.append(str(remainder))
                    
                block_idx += 1
        return ''.join(bits)
        
    # 1. Extract Length (32 bits)
    length_bits = extract_bits(32, 0)
    if not length_bits or len(length_bits) < 32:
        raise ValueError("Image doesn't contain enough blocks even for length header.")
        
    payload_length = int(length_bits, 2)
    max_payload = max_capacity // 8
    
    if payload_length <= 0 or payload_length > max_payload:
        main_logger.warning("Decoded length is nonsensical. Possibly a wrong password or non-stego image.")
        raise ValueError("Invalid decoded length. Wrong password or image corrupted.")
        
    # 2. Extract full payload bits
    total_payload_bits = payload_length * 8
    payload_bits_str = extract_bits(total_payload_bits, 32)
    
    payload_bytes = bytearray()
    for i in range(0, len(payload_bits_str), 8):
        byte_val = int(payload_bits_str[i:i+8], 2)
        payload_bytes.append(byte_val)
        
    # 3. Parse secure payload
    message = parse_secure_payload(bytes(payload_bytes), password)
    
    main_logger.info("DCT decoding successful. Message recovered.")
    return message
