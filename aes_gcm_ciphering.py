#!pip install pycryptodome
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
from datetime import datetime

def aes_gcm_encrypt(data, port=8080, address="192.168.1.1", seq_num=12345):
    # Convert the address to bytes (assuming IPv4 for simplicity)
    ip_bytes = socket.inet_aton(address)

    # Convert the port and sequence number to bytes
    port_bytes = port.to_bytes(2, 'big')
    seq_bytes = seq_num.to_bytes(4, 'big')

    # Use a consistent timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    timestamp_bytes = timestamp.encode()

    # Prepare associated data
    associated_data = ip_bytes + port_bytes + seq_bytes + timestamp_bytes

    # Generate AES key and nonce (keep these for decryption)
    key = secrets.token_bytes(32)  # 256-bit key
    nonce = secrets.token_bytes(12)  # 96-bit nonce

    # Initialize AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Authenticate additional data (AAD)
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, encryptor.tag, key, nonce, timestamp

def aes_gcm_decrypt(ciphertext, tag, key, nonce, port=8080, address="192.168.1.1", seq_num=12345, timestamp=None):
    # Convert the address to bytes
    ip_bytes = socket.inet_aton(address)

    # Convert port and sequence number to bytes
    port_bytes = port.to_bytes(2, 'big')
    seq_bytes = seq_num.to_bytes(4, 'big')

    # Use the same timestamp used during encryption
    timestamp_bytes = timestamp.encode()

    # Prepare associated data
    associated_data = ip_bytes + port_bytes + seq_bytes + timestamp_bytes

    # Initialize AES-GCM cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Authenticate the associated data (AAD)
    decryptor.authenticate_additional_data(associated_data)

    # Decrypt and return plaintext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

# Example usage
data_to_encrypt = b"Sensitive information to encrypt"

# Encrypt
ciphertext, tag, key, nonce, timestamp = aes_gcm_encrypt(data_to_encrypt)
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Tag: {tag.hex()}")

# Decrypt (using the same key, nonce, and timestamp)
decrypted_data = aes_gcm_decrypt(ciphertext, tag, key, nonce, timestamp=timestamp)
print(f"Decrypted Data: {decrypted_data.decode()}")

"""
Ciphertext: 5556385288553877658ac4a6d430e549f5dd759039a44bec5b21d7c63d29a762
Tag: a03539e85837a372b67b42b0a7adcf5e
Decrypted Data: Sensitive information to encrypt
"""
