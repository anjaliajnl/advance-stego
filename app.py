"""
Web GUI for StegoSecure using Streamlit.
Provides a modern, clean interface for cybersecurity-focused steganography.
"""
import streamlit as st
import os
import tempfile

from stego_core import encode_message, decode_message
from security_manager import security_manager
from image_utils import compute_image_hash
from jpeg_stego import is_jpeg

st.set_page_config(page_title="StegoSecure", page_icon="🔐", layout="centered")

st.title("🔐 StegoSecure")
st.subheader("Advanced Steganography Secure Messaging System")

tab1, tab2, tab3 = st.tabs(["🔒 Encode", "🔓 Decode", "ℹ️ About & CyberSec Info"])

with tab1:
    st.header("Encode a Secret Message")
    st.markdown("Hide your confidential text inside an image using AES-GCM encryption and password-derived Random LSB Steganography.")
    
    upload_img = st.file_uploader("Upload Cover Image (PNG, BMP)", type=['png', 'bmp', 'jpg', 'jpeg'], key="enc_up")
    secret_text = st.text_area("Secret Message", placeholder="Enter the text to hide...")
    enc_password = st.text_input("Encryption Password", type="password", key="enc_pass")
    
    if st.button("Encode Message", type="primary"):
        if not upload_img or not secret_text or not enc_password:
            st.error("Please provide image, message, and password.")
        else:
            with st.spinner("Encrypting and embedding..."):
                try:
                    # Save uploaded file temporarily
                    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(upload_img.name)[1]) as tmp_in:
                        tmp_in.write(upload_img.getbuffer())
                        input_path = tmp_in.name
                        
                    if is_jpeg(input_path):
                        from jpeg_stego import encode_jpeg
                        output_path = input_path.replace(os.path.splitext(input_path)[1], "_stego_dct.png")
                        encode_jpeg(input_path, secret_text, enc_password, output_path)
                        st.success("JPEG DCT Encoding Successful! Message secured in frequency domain. Output saved as PNG to prevent destructive re-compression.")
                    else:
                        output_path = input_path.replace(os.path.splitext(input_path)[1], "_stego.png")
                        
                        encode_message(input_path, secret_text, enc_password, output_path)
                        
                        st.success("Encoding Successful! The message is now secured inside the image.")
                        
                    # Provide download link
                    with open(output_path, "rb") as f:
                        st.download_button(
                            label="⬇️ Download Stego Image",
                            data=f,
                            file_name=os.path.basename(output_path),
                            mime="image/png"
                        )
                    
                    # Display Image Hash
                    img_hash = compute_image_hash(output_path)
                    st.info(f"**Image SHA-256 Hash:** `{img_hash}`\nSave this to verify file integrity later.")
                        
                except ValueError as ve:
                    st.error(f"Error: {str(ve)}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {str(e)}")

with tab2:
    st.header("Decode a Secret Message")
    
    decode_img = st.file_uploader("Upload Stego Image", type=['png', 'bmp'], key="dec_up")
    dec_password = st.text_input("Decryption Password", type="password", key="dec_pass")
    
    if st.button("Decode Message", type="primary"):
        if security_manager.is_locked_out():
            st.error("System locked due to excessive failed attempts. Please wait.")
        elif not decode_img or not dec_password:
            st.warning("Please upload an image and enter the password.")
        else:
            with st.spinner("Extracting, verifying, and decrypting..."):
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_in:
                        tmp_in.write(decode_img.getbuffer())
                        input_path = tmp_in.name
                        
                    if "_stego_dct" in decode_img.name or is_jpeg(decode_img.name):
                        from jpeg_stego import decode_jpeg
                        secret = decode_jpeg(input_path, dec_password)
                    else:
                        secret = decode_message(input_path, dec_password)
                        
                    security_manager.record_success()
                    
                    st.success("Message Successfully Decoded and Verified!")
                    st.text_area("Recovered Secret Message", value=secret, height=150, disabled=False)
                    
                except ValueError as ve:
                    security_manager.record_failed_attempt()
                    st.error(f"Failed to decode: {str(ve)}")
                except Exception as e:
                    security_manager.record_failed_attempt()
                    st.error("Failed to decode. The data might be corrupted or tampered with.")

with tab3:
    st.header("How it Works")
    st.markdown("""
    **StegoSecure** goes far beyond basic LSB (Least Significant Bit) steganography by layering multiple cybersecurity principles:
    
    1. **Compression (zlib)**: Reduces payload size, increasing image capacity.
    2. **Integrity (SHA-256)**: Computes a hash of the original message to detect tampering.
    3. **Confidentiality & Authentication (AES-GCM)**: Authenticated encryption ensures only the password holder can read the message, and actively verifies if the bits were modified.
    4. **Secure Key Derivation (PBKDF2)**: Defends against dictionary attacks by using 480,000 rounds of hashing with a random salt to generate the AES key.
    5. **Randomized Steganography (Key-Based PRNG)**: Instead of filling LSBs sequentially, bits are scattered across the image based on a random sequence seeded by the derived key. This reduces detectability by classical steganalysis tools.
    6. **Brute-Force Protection**: Logs failed decoding attempts and locks the system after repeated failures.
    """)
