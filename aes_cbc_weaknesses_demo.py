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

def cbc_mac(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + b"\x00" * (16 - len(message) % 16)
    mac = encryptor.update(padded_message) + encryptor.finalize()
    return mac[-16:]

def cbc_mac_forgery_example():
    key = get_random_bytes(32)
    iv = b"\x00" * 16

    message1 = b"OriginalMessage"
    tag1 = cbc_mac(message1, key, iv)

    message2 = b"ForgedMessage"
    modified_message2 = bytes([m ^ t for m, t in zip(message2[:16], tag1)]) + message2[16:]

    tag2 = cbc_mac(modified_message2, key, iv)

    combined_message = message1 + message2
    combined_tag = tag2

    print("Original Message 1:", message1)
    print("Original Tag 1:", tag1.hex())
    print("Modified Message 2:", modified_message2)
    print("Forged Tag 2:", tag2.hex())
    print("Valid MAC for Combined Message:", combined_message)

def random_iv_attack_example():
    key = get_random_bytes(32)

    message = b"SensitiveData"
    iv = get_random_bytes(16)

    original_tag = cbc_mac(message, key, iv)

    altered_iv = bytes([iv[0] ^ 1]) + iv[1:]

    tampered_tag = cbc_mac(message, key, altered_iv)

    print("Original IV:", iv.hex())
    print("Original Tag:", original_tag.hex())
    print("Altered IV:", altered_iv.hex())
    print("Tampered Tag:", tampered_tag.hex())

if __name__ == "__main__":
    key = get_random_bytes(32)  # AES-256 key
    plaintext = b"Confidential message"

    encrypted_ctr = encrypt_ctr(plaintext, key)
    print("Encrypted (CTR):", encrypted_ctr.hex())

    decrypted_ctr = decrypt_ctr(encrypted_ctr, key)
    print("Decrypted (CTR):", decrypted_ctr.decode())

    print("\n--- CBC-MAC Forgery Example ---")
    cbc_mac_forgery_example()

    print("\n--- Random IV Attack Example ---")
    random_iv_attack_example()




"""
Encrypted (CTR): 7e0781257e0bef4a69b9903d4274c374ce6c4bfc94b5783e634edd936334fdf94a70cc32b144369b07ce0f7b78b6e813435667b05c7543c51e0cb6a43a2ca5b46b340155
Decrypted (CTR): Confidential message

--- CBC-MAC Forgery Example ---
Original Message 1: b'OriginalMessage'
Original Tag 1: 0a3f682207c31b7b7d2a3df472289ee1
Modified Message 2: b'LP\x1aEb\xa7V\x1e\x0eY\\\x93\x17'
Forged Tag 2: e225008584e38caa0737e7d378388d4d
Valid MAC for Combined Message: b'OriginalMessageForgedMessage'

--- Random IV Attack Example ---
Original IV: 999dda3176f7ff62707799375cebb570
Original Tag: 9cd21bd69fee30cace62e09ee8d314ee
Altered IV: 989dda3176f7ff62707799375cebb570
Tampered Tag: 2f2ccf8c8892bdac16e4dcbb71d78a9e
"""