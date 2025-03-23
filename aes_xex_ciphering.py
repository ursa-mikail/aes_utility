import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Helper function to XOR two byte strings
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Padding function (PKCS7 standard)
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

# Unpadding function (PKCS7 standard)
def unpad(data):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

# AES-XEX Encryption
def aes_xex_encrypt(key, tweak, plaintext):
    if len(key) not in (16, 32):
        raise ValueError("Key must be either 16 or 32 bytes long (AES-128/256)")
    if len(tweak) != 16:
        raise ValueError("Tweak must be 16 bytes long")

    # Pad the plaintext to be a multiple of 16 bytes
    plaintext = pad(plaintext)

    # Create AES cipher in ECB mode (no IV needed)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    
    # Encrypt tweak
    encryptor = cipher.encryptor()
    encrypted_tweak = encryptor.update(tweak) + encryptor.finalize()

    # XOR plaintext with encrypted tweak
    xored_plaintext = xor_bytes(plaintext, encrypted_tweak)

    # Recreate encryptor for encryption (to avoid AlreadyFinalized error)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(xored_plaintext) + encryptor.finalize()

    # Final XOR with encrypted tweak
    return xor_bytes(ciphertext, encrypted_tweak)

# AES-XEX Decryption
def aes_xex_decrypt(key, tweak, ciphertext):
    if len(key) not in (16, 32):
        raise ValueError("Key must be either 16 or 32 bytes long (AES-128/256)")
    if len(tweak) != 16:
        raise ValueError("Tweak must be 16 bytes long")

    # Create AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    
    # Encrypt tweak (for decryption)
    encryptor = cipher.encryptor()
    encrypted_tweak = encryptor.update(tweak) + encryptor.finalize()

    # XOR ciphertext with encrypted tweak
    xored_ciphertext = xor_bytes(ciphertext, encrypted_tweak)

    # Decrypt XORed data
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(xored_ciphertext) + decryptor.finalize()

    # Final XOR with encrypted tweak
    plaintext = xor_bytes(decrypted, encrypted_tweak)

    # Remove padding
    return unpad(plaintext)

# Example usage
key = os.urandom(32)          # AES-256 key (32 bytes)
tweak = os.urandom(16)        # Tweak (16 bytes)
plaintext = b"SensitiveData!"

# Encrypt and decrypt
ciphertext = aes_xex_encrypt(key, tweak, plaintext)
decrypted_text = aes_xex_decrypt(key, tweak, ciphertext)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted: {decrypted_text}")

"""
AES requiring input data to be a multiple of the block size (16 bytes) when using ECB mode. AES operates on fixed-size blocks (128 bits = 16 bytes), so any input that isn’t a multiple of 16 bytes will raise a ValueError.

📘 Note:
Pad the plaintext if it is not a multiple of 16 bytes.

Remove padding after decryption.

Padding: We apply PKCS#7 padding to make the plaintext length a multiple of 16 bytes.

XOR Operations: Each encryption and decryption step XORs the data with the encrypted tweak.

Cipher Context Management: We recreate the AES cipher context after each encryption or decryption step to avoid the AlreadyFinalized error.

Ensure the tweak is unique for each encryption operation to maintain security.

AES-XEX is often used in disk encryption but not ideal for general-purpose message encryption. Consider AES-GCM or AES-CCM if authentication is required.

✅
Plaintext: b'SensitiveData!'
Ciphertext (hex): bd8c68445db1aac29286d38c984044e5
Decrypted: b'SensitiveData!'
"""
