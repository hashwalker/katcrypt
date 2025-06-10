"""
KatCrypt - A unified cryptographic library supporting AES and MARS ciphers
with multiple modes of operation.

Usage:
from katcrypt.ciphers.threefish import Threefish
from katcrypt.modes.gcm import GCM
from katcrypt import encrypt, decrypt
from katcrypt.utils import generate_key, generate_iv

plaintext = b"Hello World!"
key = generate_key(1024)
iv = generate_iv(16)
aad = b"AAD"

threefish_gcm = GCM(Threefish(key=key))

ciphertext, tag = threefish_gcm.encrypt(plaintext=plaintext, iv=iv, aad=aad)
print(f"Ciphertext: {ciphertext}")

decrypted = threefish_gcm.decrypt(ciphertext=ciphertext, iv=iv, aad=aad, auth_tag=tag)
print(f"Decrypted: {decrypted}")
"""

# Import both encrypt and decrypt functions
from .encrypt import encrypt
from .decrypt import decrypt

__version__ = "0.1.3"
__author__ = "Hashwalker"

# Expose both functions at package level
__all__ = ['encrypt', 'decrypt']

# Supported algorithms for reference
SUPPORTED_CIPHERS = ['aes', 'mars', 'threefish']
SUPPORTED_MODES = ['cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb']