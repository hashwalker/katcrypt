"""
KatCrypt - Unified Decryption API

This module provides a high-level interface for decryption operations
combining AES, MARS, and Threefish ciphers with different modes of operation.
"""

from typing import Union, Optional

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


def decrypt(cipher: str,
            mode: str,
            key: Union[str, bytes],
            ciphertext: bytes,
            iv: Optional[Union[str, bytes]] = None,
            nonce: Optional[Union[str, bytes]] = None,
            auth_tag: Optional[bytes] = None,
            aad: Union[str, bytes] = b"",
            tweak: Optional[bytes] = None,
            tag_length: Optional[int] = None) -> bytes:
    """
    Decrypt ciphertext using specified cipher and mode.

    Args:
        cipher: Cipher algorithm name ('aes', 'mars', 'threefish')
        mode: Mode of operation ('cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb')
        key: Decryption key (string or bytes)
        ciphertext: Data to decrypt
        iv: Initialization vector for modes that require it
        nonce: Nonce for CTR/GCM modes (alternative to iv)
        auth_tag: Authentication tag (for GCM mode)
        aad: Additional authenticated data (for GCM mode)
        tweak: Tweak parameter (for Threefish cipher only)
        tag_length: Authentication tag length (for GCM mode, defaults based on block size)

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: If cipher/mode combination is invalid or parameters are missing

    Examples:
        # Basic AES-CBC decryption
        plaintext = decrypt("aes", "cbc", "my_secret_key", ciphertext, iv=iv)

        # AES-GCM with authentication
        plaintext = decrypt("aes", "gcm", key, ciphertext, iv=iv, auth_tag=tag, aad="metadata")

        # MARS-CTR with nonce
        plaintext = decrypt("mars", "ctr", key, ciphertext, nonce=nonce)

        # Threefish-ECB with tweak
        plaintext = decrypt("threefish", "ecb", key, ciphertext, tweak=my_tweak)

        # Threefish-GCM with custom tag length
        plaintext = decrypt("threefish", "gcm", key, ciphertext, iv=iv, auth_tag=tag, tag_length=32)
    """
    # Validate inputs
    if cipher not in CIPHERS:
        raise ValueError(f"Unsupported cipher: {cipher}. Available: {list(CIPHERS.keys())}")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}. Available: {list(MODES.keys())}")

    # Convert strings to bytes
    if isinstance(key, str):
        key = key.encode('utf-8')
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
        return mode_instance.decrypt(ciphertext)

    elif mode in ['cbc', 'cfb', 'ofb']:
        # These modes need IV
        if iv is None:
            raise ValueError(f"IV is required for {mode.upper()} mode")
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        return mode_instance.decrypt(ciphertext, iv)

    elif mode == 'ctr':
        # CTR mode uses nonce
        if nonce is None and iv is None:
            raise ValueError("Nonce is required for CTR mode")
        elif iv is not None:
            nonce = iv
        if isinstance(nonce, str):
            nonce = nonce.encode('utf-8')
        return mode_instance.decrypt(ciphertext, nonce)

    elif mode == 'gcm':
        # GCM mode uses IV, auth_tag, and AAD
        if iv is None:
            raise ValueError("IV is required for GCM mode")
        if auth_tag is None:
            raise ValueError("Authentication tag is required for GCM mode")
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        return mode_instance.decrypt(ciphertext, iv, auth_tag, aad)