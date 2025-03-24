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

def derive_keys(key):
    encKey = hkdf(key, b"encryption-cbc-hmac", b"AES-CBC encryption key")
    macKey = hkdf(key, b"authentication-cbc-hmac", b"HMAC authentication key")
    return encKey, macKey

def encrypt(plaintext, key):
    encKey, macKey = derive_keys(key)
    iv = get_random_bytes(16)

    cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    tag = hmac.new(macKey, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + tag

def decrypt(ciphertext, key):
    encKey, macKey = derive_keys(key)

    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:-32]
    received_tag = ciphertext[-32:]

    expected_tag = hmac.new(macKey, iv + actual_ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("MAC verification failed")

    cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return unpad(padded_plaintext)

def pad(plaintext, block_size=16):
    padding_len = block_size - len(plaintext) % block_size
    return plaintext + bytes([padding_len] * padding_len)

def unpad(padded_plaintext):
    padding_len = padded_plaintext[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    return padded_plaintext[:-padding_len]

if __name__ == "__main__":
    key = get_random_bytes(32)  # AES-256 key
    plaintext = b"Confidential message"

    encrypted = encrypt(plaintext, key)
    print("Encrypted:", encrypted.hex())

    decrypted = decrypt(encrypted, key)
    print("Decrypted:", decrypted.decode())

"""
Encrypted: 219a693e4349eb74b563fce482431820bc48452fde196c637770cae17cc51fbbdef03cba61d9e4c0b7238852afbf97a6710cd7a3b997e01939226c38f64f708acf8bfefe93019f6b3d515d90cb631402
Decrypted: Confidential message
"""