"""
Galois/Counter Mode (GCM)

GCM is an authenticated encryption mode that combines CTR mode encryption
with GHASH authentication. It provides both confidentiality and authenticity,
ensuring that encrypted data cannot be tampered with. GCM is widely used in
modern protocols like TLS 1.3.
"""

from katcrypt.modes.ctr import CTR
from katcrypt.utils import ghash, increment_counter_32, constant_time_compare, gf_multiply


class GCM:
    """
    Galois/Counter Mode (GCM) authenticated encryption.

    GCM combines CTR mode encryption with GHASH authentication to provide
    both confidentiality and authenticity. It uses a hash subkey H derived
    from encrypting a zero block, and computes authentication over both
    additional authenticated data (AAD) and the ciphertext.
    """

    def __init__(self, cipher, tag_length: int = 16):
        """
        Initialize GCM mode with a block cipher.

        Args:
            cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
        """
        self.cipher = cipher
        self.ctr_mode = CTR(cipher)
        self.block_size = cipher.block_size
        self.tag_length = tag_length

    def encrypt(self, plaintext: bytes, iv: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        """
        Encrypt plaintext using GCM mode and compute authentication tag.

        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (nonce)
            aad: Additional authenticated data (not encrypted but authenticated)

        Returns:
            Tuple of (ciphertext, authentication_tag)

        Raises:
            ValueError: If IV is empty
        """
        if not iv:
            raise ValueError("IV must be non-empty")

        # Generate hash subkey H by encrypting zero block
        hash_subkey = self.cipher.encrypt_block(b"\x00" * self.block_size)

        if len(iv) == self.block_size - 4:
            # For standard IV (block_size - 4 bytes):
            initial_counter = iv + (1).to_bytes(4, "big")
        else:
            # For non-standard IVs, compute GHASH directly
            # Pad IV to multiple of block_size bytes
            rem = len(iv) % self.block_size
            iv_padded = iv + b"\x00" * ((self.block_size - rem) % self.block_size)

            # Build length block: 0^(block_size//2*8) || len(IV) in bits
            iv_len_bits = len(iv) * 8
            half_block = self.block_size // 2
            length_block = (0).to_bytes(half_block, "big") + iv_len_bits.to_bytes(half_block, "big")

            # Compute GHASH manually for IV processing
            # GHASH(H, {}, IV) = GHASH over (iv_padded || length_block)
            hash_accumulator = b'\x00' * self.block_size

            # Process IV blocks
            for i in range(0, len(iv_padded), self.block_size):
                block = iv_padded[i:i + self.block_size]
                hash_accumulator = gf_multiply(
                    bytes(a ^ b for a, b in zip(block, hash_accumulator)),
                    hash_subkey
                )

            # Process length block
            hash_accumulator = gf_multiply(
                bytes(a ^ b for a, b in zip(length_block, hash_accumulator)),
                hash_subkey
            )

            initial_counter = hash_accumulator
            # Ensure initial_counter is padded to block size
            if len(initial_counter) != self.block_size:
                initial_counter = initial_counter.ljust(self.block_size, b'\x00')

        # Generate first counter for CTR encryption (J0 + 1)
        encryption_counter = increment_counter_32(initial_counter)

        # Encrypt plaintext using CTR mode
        ciphertext = self.ctr_mode.encrypt(plaintext, encryption_counter)

        # Compute GHASH over AAD and ciphertext
        ghash_result = ghash(hash_subkey, aad, ciphertext)
        # Ensure GHASH result is full block_size
        ghash_result = ghash_result.ljust(self.block_size, b"\x00")

        encrypted_j0 = self.cipher.encrypt_block(initial_counter)
        tag_raw = bytes(a ^ b for a, b in zip(encrypted_j0, ghash_result))
        authentication_tag = tag_raw[:self.tag_length]

        return ciphertext, authentication_tag

    def decrypt(self, ciphertext: bytes, iv: bytes, auth_tag: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt ciphertext using GCM mode and verify authentication tag.

        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (nonce)
            auth_tag: Authentication tag to verify
            aad: Additional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If IV is empty, auth tag is wrong length, or authentication fails
        """
        if not iv:
            raise ValueError("IV must be non-empty")
        if len(auth_tag) != self.tag_length:
            raise ValueError(f"Authentication tag must be {self.tag_length} bytes")

        # Generate hash subkey H by encrypting zero block
        hash_subkey = self.cipher.encrypt_block(b"\x00" * self.block_size)

        # Compute initial counter J0 based on IV length
        if len(iv) == self.block_size - 4:
            # For standard IV (block_size - 4 bytes):
            initial_counter = iv + (1).to_bytes(4, "big")
        else:
            # For non-standard IVs, compute GHASH directly
            # Pad IV to multiple of block_size bytes
            rem = len(iv) % self.block_size
            iv_padded = iv + b"\x00" * ((self.block_size - rem) % self.block_size)

            # Build length block: 0^(block_size//2*8) || len(IV) in bits
            iv_len_bits = len(iv) * 8
            half_block = self.block_size // 2
            length_block = (0).to_bytes(half_block, "big") + iv_len_bits.to_bytes(half_block, "big")

            # Compute GHASH manually for IV processing
            # GHASH(H, {}, IV) = GHASH over (iv_padded || length_block)
            hash_accumulator = b'\x00' * self.block_size

            # Process IV blocks
            for i in range(0, len(iv_padded), self.block_size):
                block = iv_padded[i:i + self.block_size]
                hash_accumulator = gf_multiply(
                    bytes(a ^ b for a, b in zip(block, hash_accumulator)),
                    hash_subkey
                )

            # Process length block
            hash_accumulator = gf_multiply(
                bytes(a ^ b for a, b in zip(length_block, hash_accumulator)),
                hash_subkey
            )

            initial_counter = hash_accumulator
            # Ensure initial_counter is padded to block size
            if len(initial_counter) != self.block_size:
                initial_counter = initial_counter.ljust(self.block_size, b'\x00')

        # Generate first counter for CTR decryption (J0 + 1)
        decryption_counter = increment_counter_32(initial_counter)

        # Decrypt ciphertext using CTR mode (same as encryption)
        plaintext = self.ctr_mode.decrypt(ciphertext, decryption_counter)

        # Compute GHASH over AAD and ciphertext for verification
        ghash_result = ghash(hash_subkey, aad, ciphertext)
        ghash_result = ghash_result.ljust(self.block_size, b"\x00")

        # Compute expected authentication tag
        encrypted_j0 = self.cipher.encrypt_block(initial_counter)
        expected_tag = bytes(a ^ b for a, b in zip(encrypted_j0, ghash_result))
        expected_tag = expected_tag[:self.tag_length]

        # Verify authentication tag in constant time
        if not constant_time_compare(auth_tag, expected_tag):
            raise ValueError("Authentication tag does not match — data integrity compromised")

        return plaintext