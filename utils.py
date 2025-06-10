"""
Cryptographic Utility Functions

This module provides common utility functions used throughout katcrypt,
including secure key generation, padding operations, and other helper functions.
"""

import secrets

def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes, removing spaces."""
    return bytes.fromhex(hex_string.replace(" ", ""))

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()

def generate_key(bits: int = 256) -> bytes:
    """Generate a cryptographically secure random key."""
    if bits % 32 != 0:
        raise ValueError("Key size must be divisible by 32 bits")
    return secrets.token_bytes(bits // 8)

def generate_iv(size: int = 16) -> bytes:
    """Generate a random initialization vector."""
    return secrets.token_bytes(size)

def generate_nonce(size: int = 12) -> bytes:
    """Generate a random nonce."""
    return secrets.token_bytes(size)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not padded_data:
        raise ValueError("Cannot unpad empty data")

    padding_length = padded_data[-1]
    if padding_length == 0 or padding_length > len(padded_data):
        raise ValueError("Invalid padding")

    expected_padding = bytes([padding_length] * padding_length)
    actual_padding = padded_data[-padding_length:]

    if expected_padding != actual_padding:
        raise ValueError("Invalid padding")

    return padded_data[:-padding_length]

def constant_time_compare(left_bytes: bytes, right_bytes: bytes) -> bool:
    """Compare two byte sequences in constant time to prevent timing attacks."""
    if len(left_bytes) != len(right_bytes):
        return False

    accumulated_difference = 0
    for left_byte, right_byte in zip(left_bytes, right_bytes):
        accumulated_difference |= left_byte ^ right_byte

    return accumulated_difference == 0

def increment_counter_32(counter_block: bytes) -> bytes:
    """
    Increment the last 32 bits of a counter block (used in CTR/GCM mode).
    Works for any block size ≥ 4 bytes.
    """
    if len(counter_block) < 4:
        raise ValueError("Counter block must be at least 4 bytes")

    # Split: everything except last 4 bytes (prefix) + last 4 bytes (counter)
    prefix = counter_block[:-4]
    counter_value = int.from_bytes(counter_block[-4:], 'big')
    counter_value = (counter_value + 1) % (1 << 32)

    return prefix + counter_value.to_bytes(4, 'big')


#####################################
# GCM Utilities
#####################################

def gf_multiply(operand_x: bytes, operand_y: bytes) -> bytes:
    """Multiply two elements in GF(2^128) for GHASH."""
    reduction_polynomial = 0xe1000000000000000000000000000000

    x_int = int.from_bytes(operand_x, 'big')
    y_int = int.from_bytes(operand_y, 'big')
    result_int = 0

    for bit_position in range(128):
        if (y_int >> (127 - bit_position)) & 1:
            result_int ^= x_int

        if x_int & 1:
            x_int = (x_int >> 1) ^ reduction_polynomial
        else:
            x_int >>= 1

    result_int &= (1 << 128) - 1
    return result_int.to_bytes(16, 'big')


def ghash(hash_subkey: bytes, auth_data: bytes, ciphertext: bytes) -> bytes:
    """Compute GHASH for GCM authentication."""
    formatted_data = _build_ghash_input(auth_data, ciphertext)
    hash_accumulator = b'\x00' * 16

    for block_index in range(0, len(formatted_data), 16):
        block = formatted_data[block_index:block_index + 16]
        hash_accumulator = gf_multiply(
            bytes(block_byte ^ accum_byte for block_byte, accum_byte in zip(block, hash_accumulator)),
            hash_subkey
        )

    return hash_accumulator

def _build_ghash_input(auth_data: bytes, ciphertext: bytes) -> bytes:
    """Build the input for GHASH computation."""
    def pad_to_block_size(data: bytes) -> bytes:
        if len(data) % 16 == 0:
            return data
        return data + b'\x00' * (16 - len(data) % 16)

    padded_auth_data = pad_to_block_size(auth_data)
    padded_ciphertext = pad_to_block_size(ciphertext)

    auth_data_bit_length = (len(auth_data) * 8).to_bytes(8, 'big')
    ciphertext_bit_length = (len(ciphertext) * 8).to_bytes(8, 'big')

    return padded_auth_data + padded_ciphertext + auth_data_bit_length + ciphertext_bit_length