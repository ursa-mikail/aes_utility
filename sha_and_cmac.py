# sha256
import hashlib
import requests

# List of URLs
urls = [
    "https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/bad.html",
    "https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/good.html",
    "https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/index.html"
]

# Function to fetch content and compute SHA256 hash
def fetch_and_compute_sha256(url):
    response = requests.get(url)
    content = response.text.encode('utf-8')  # Ensure the content is in bytes
    sha256_hash = hashlib.sha256(content).hexdigest()
    return sha256_hash

# Compute and print the hashes for each URL
for url in urls:
    hash_value = fetch_and_compute_sha256(url)
    print(f"SHA256 for {url}: {hash_value}")


# CMAC
import os
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms


# Function to fetch content and compute SHA256 hash
def fetch_and_compute_sha256(url):
    response = requests.get(url)
    content = response.text.encode('utf-8')  # Ensure the content is in bytes
    sha256_hash = hashlib.sha256(content).hexdigest()
    return content, sha256_hash

# Function to compute CMAC
def compute_cmac(data, key):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize().hex()

# Generate a key for CMAC (in real applications, this should be securely stored)
key = os.urandom(16)  # 128-bit key for AES-CMAC

print(f"CMAC Key (hex): {key.hex()}")
print("\n=== URL Content Verification ===\n")

# Compute and print the hashes for each URL
for url in urls:
    content, hash_value = fetch_and_compute_sha256(url)
    cmac_value = compute_cmac(content, key)
    
    print(f"URL: {url}")
    print(f"SHA256: {hash_value}")
    print(f"CMAC: {cmac_value}")
    print("-" * 60)

"""
SHA256 for https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/bad.html: 646d6b32f05643995179d0ee6df947be64e3f6dfd62502dd09cf588fdb48099a
SHA256 for https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/good.html: b89a3aaf76258663104201be3630a1d18ac4cb8be8c837c946133d7e6c616d9a
SHA256 for https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/index.html: 7db2d0ffb149ad491351b78af589587e1303163f83fcbb7f310e27217c3dfa80
CMAC Key (hex): 666668c723cd5215b3e76f269a583278

=== URL Content Verification ===

URL: https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/bad.html
SHA256: 646d6b32f05643995179d0ee6df947be64e3f6dfd62502dd09cf588fdb48099a
CMAC: 08d22ffde3b7e4a1423af2707e3ec540
------------------------------------------------------------
URL: https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/good.html
SHA256: b89a3aaf76258663104201be3630a1d18ac4cb8be8c837c946133d7e6c616d9a
CMAC: a5c52ee74b6ac3f15ed7f4659a94fa14
------------------------------------------------------------
URL: https://ursa-mikail.github.io/site_announcement/announcement/simple_with_checking/index.html
SHA256: 7db2d0ffb149ad491351b78af589587e1303163f83fcbb7f310e27217c3dfa80
CMAC: d8a89966627e766857bbb9f4c2f13d23
------------------------------------------------------------
"""    