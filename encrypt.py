"""
KatCrypt - Unified Encryption API

This module provides a high-level interface for encryption operations
combining AES, MARS, and Threefish ciphers with different modes of operation.
"""

import os
from typing import Union, Tuple, Optional

# Import cipher implementations
from katcrypt.ciphers.aes import AES
from katcrypt.ciphers.mars import MARS
from katcrypt.ciphers.threefish import Threefish

# Import mode implementations
from katcrypt.modes.cbc import CBC
from katcrypt.modes.cfb import CFB
from katcrypt.modes.ctr import CTR
from katcrypt.modes.ecb import ECB
from katcrypt.modes.gcm import GCM
from katcrypt.modes.ofb import OFB


# Registry of available ciphers
CIPHERS = {
    'aes': AES,
    'mars': MARS,
    'threefish': Threefish,
}

# Registry of available modes
MODES = {
    'cbc': CBC,
    'cfb': CFB,
    'ctr': CTR,
    'ecb': ECB,
    'gcm': GCM,
    'ofb': OFB,
}


def encrypt(cipher: str,
           mode: str,
           key: Union[str, bytes],
           plaintext: Union[str, bytes],
           iv: Optional[Union[str, bytes]] = None,
           nonce: Optional[Union[str, bytes]] = None,
           aad: Union[str, bytes] = b"",
           tweak: Optional[bytes] = None,
           tag_length: Optional[int] = None) -> Union[bytes, Tuple[bytes, bytes]]:
    """
    Encrypt plaintext using specified cipher and mode.

    Args:
        cipher: Cipher algorithm name ('aes', 'mars', 'threefish')
        mode: Mode of operation ('cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb')
        key: Encryption key (string or bytes)
        plaintext: Data to encrypt (string or bytes)
        iv: Initialization vector for modes that require it
        nonce: Nonce for CTR/GCM modes (alternative to iv)
        aad: Additional authenticated data (for GCM mode)
        tweak: Tweak parameter (for Threefish cipher only)
        tag_length: Authentication tag length (for GCM mode, defaults based on block size)

    Returns:
        For most modes: ciphertext bytes
        For GCM mode: tuple of (ciphertext, auth_tag)

    Raises:
        ValueError: If cipher/mode combination is invalid or parameters are missing

    Examples:
        # Basic AES-CBC encryption
        ciphertext = encrypt("aes", "cbc", "my_secret_key", "Hello World!")

        # AES-GCM with authentication
        ciphertext, auth_tag = encrypt("aes", "gcm", key, plaintext, aad="metadata")

        # MARS-CTR with custom nonce
        ciphertext = encrypt("mars", "ctr", key, plaintext, nonce=my_nonce)

        # Threefish-ECB with tweak
        ciphertext = encrypt("threefish", "ecb", key, plaintext, tweak=my_tweak)

        # Threefish-GCM with custom tag length
        ciphertext, tag = encrypt("threefish", "gcm", key, plaintext, tag_length=32)
    """
    # Validate inputs
    if cipher not in CIPHERS:
        raise ValueError(f"Unsupported cipher: {cipher}. Available: {list(CIPHERS.keys())}")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}. Available: {list(MODES.keys())}")

    # Convert strings to bytes
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(aad, str):
        aad = aad.encode('utf-8')

    # Initialize cipher
    cipher_class = CIPHERS[cipher]
    if cipher == 'threefish':
        # Threefish supports optional tweak parameter
        cipher_instance = cipher_class(key, tweak=tweak)
    else:
        cipher_instance = cipher_class(key)

    # Initialize mode
    mode_class = MODES[mode]
    if mode == 'gcm':
        # GCM mode supports custom tag length
        if tag_length is None:
            # Use sensible defaults based on block size
            if cipher == 'threefish':
                # For Threefish, use smaller tag lengths for practicality
                tag_length = min(32, cipher_instance.block_size // 2)
            else:
                # Standard 16-byte tag for AES/MARS
                tag_length = 16
        mode_instance = mode_class(cipher_instance, tag_length=tag_length)
    else:
        mode_instance = mode_class(cipher_instance)

    # Handle different mode requirements
    if mode == 'ecb':
        # ECB doesn't need IV
        return mode_instance.encrypt(plaintext)

    elif mode in ['cbc', 'cfb', 'ofb']:
        # These modes need IV
        if iv is None:
            iv = os.urandom(cipher_instance.block_size)
        elif isinstance(iv, str):
            iv = iv.encode('utf-8')
        return mode_instance.encrypt(plaintext, iv)

    elif mode == 'ctr':
        # CTR mode uses nonce
        if nonce is None and iv is None:
            nonce = os.urandom(cipher_instance.block_size // 2)
        elif iv is not None:
            nonce = iv
        if isinstance(nonce, str):
            nonce = nonce.encode('utf-8')
        return mode_instance.encrypt(plaintext, nonce)

    elif mode == 'gcm':
        # GCM mode uses IV and AAD
        if iv is None:
            # Use standard 12-byte IV for GCM regardless of block size
            iv = os.urandom(12)
        elif isinstance(iv, str):
            iv = iv.encode('utf-8')
        return mode_instance.encrypt(plaintext, iv, aad)