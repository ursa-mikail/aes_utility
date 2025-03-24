#!pip install pycryptodome
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes

def hkdf(key, salt, info, length=32):
    prk = hmac.new(salt, key, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1

    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    return okm[:length]

def derive_keys(key, enc_info, mac_info):
    encKey = hkdf(key, enc_info, b"AES encryption key")
    macKey = hkdf(key, mac_info, b"HMAC authentication key")
    return encKey, macKey

def encrypt_ctr(plaintext, key):
    encKey, macKey = derive_keys(key, b"encryption-ctr-hmac", b"authentication-ctr-hmac")
    nonce = get_random_bytes(16)

    cipher = Cipher(algorithms.AES(encKey), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    tag = hmac.new(macKey, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag

def decrypt_ctr(ciphertext, key):
    encKey, macKey = derive_keys(key, b"encryption-ctr-hmac", b"authentication-ctr-hmac")

    nonce = ciphertext[:16]
    actual_ciphertext = ciphertext[16:-32]
    received_tag = ciphertext[-32:]

    expected_tag = hmac.new(macKey, nonce + actual_ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("MAC verification failed")

    cipher = Cipher(algorithms.AES(encKey), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()

if __name__ == "__main__":
    key = get_random_bytes(32)  # AES-256 key
    plaintext = b"Confidential message"

    encrypted_ctr = encrypt_ctr(plaintext, key)
    print("Encrypted (CTR):", encrypted_ctr.hex())

    decrypted_ctr = decrypt_ctr(encrypted_ctr, key)
    print("Decrypted (CTR):", decrypted_ctr.decode())


"""
Encrypted (CTR): e65cde9eab75349353b9f944344391eafab27846f75b5f28020c80bbd3765e28112142f34cb284b1e0797c8c7b0d960e01a78b3b88683c2e65dd866ffa42657dd43f6755
Decrypted (CTR): Confidential message
"""