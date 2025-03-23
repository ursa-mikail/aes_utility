#!pip install pycryptodome
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AES-XTS Encryption
def aes_xts_encrypt(key1, key2, plaintext, sector_number):
    if len(key1) != 32 or len(key2) != 32:
        raise ValueError("AES-XTS requires two 256-bit (32-byte) keys")
    
    # Combine keys for XTS mode
    combined_key = key1 + key2
    
    # XTS requires a 128-bit (16-byte) tweak, usually the sector number
    tweak = sector_number.to_bytes(16, 'little')
    
    # Create AES-XTS cipher
    cipher = Cipher(algorithms.AES(combined_key), modes.XTS(tweak), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext

# AES-XTS Decryption
def aes_xts_decrypt(key1, key2, ciphertext, sector_number):
    if len(key1) != 32 or len(key2) != 32:
        raise ValueError("AES-XTS requires two 256-bit (32-byte) keys")
    
    # Combine keys for XTS mode
    combined_key = key1 + key2
    
    # XTS requires a 128-bit (16-byte) tweak
    tweak = sector_number.to_bytes(16, 'little')
    
    # Create AES-XTS cipher
    cipher = Cipher(algorithms.AES(combined_key), modes.XTS(tweak), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

# Example Usage
key1 = os.urandom(32)  # First part of 512-bit key (32 bytes)
key2 = os.urandom(32)  # Second part of 512-bit key (32 bytes)
sector_number = 42     # Example sector number (for tweak)
plaintext = b"Data to encrypt using AES-XTS mode."

# Ensure plaintext length is a multiple of 16 bytes (block size)
if len(plaintext) % 16 != 0:
    padding = 16 - (len(plaintext) % 16)
    plaintext += b'\x00' * padding

# Encrypt and decrypt
ciphertext = aes_xts_encrypt(key1, key2, plaintext, sector_number)
decrypted_text = aes_xts_decrypt(key1, key2, ciphertext, sector_number)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted: {decrypted_text}")

"""
Plaintext: b'Data to encrypt using AES-XTS mode.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Ciphertext (hex): 6be6d7c9ff52727ccc0c7e24efbcb5064c976e7aa2843ec995804fe37ab569598f309d28a91eff51fba7c4030e632d1f
Decrypted: b'Data to encrypt using AES-XTS mode.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
"""
