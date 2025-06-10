"""
Cipher Feedback (CFB) Mode

CFB is a block cipher mode that operates like a stream cipher. The block cipher
encrypts the initialization vector (or previous ciphertext block) to produce
a keystream, which is then XORed with the plaintext. CFB mode can operate with
feedback sizes smaller than the block size, making it suitable for encrypting
data that doesn't align with block boundaries.
"""

from katcrypt.utils import pkcs7_pad, pkcs7_unpad


class CFB:
    """
    Cipher Feedback (CFB) mode of operation.

    In CFB mode, the block cipher encrypts the previous ciphertext block (or IV)
    to create a keystream that is XORed with the plaintext:
    C[0] = P[0] ⊕ E(K, IV)
    C[i] = P[i] ⊕ E(K, C[i-1]) for i > 0

    CFB mode turns a block cipher into a stream cipher and does not require padding.
    """

    def __init__(self, cipher):
        """
        Initialize CFB mode with a block cipher.

        Args:
            cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
        """
        self.cipher = cipher
        self.block_size = cipher.block_size

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt plaintext using CFB mode.

        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (must be block_size bytes)

        Returns:
            Encrypted ciphertext

        Raises:
            ValueError: If IV length doesn't match block size
        """
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes.")

        ciphertext = bytearray()
        previous_block = iv

        # Process data in chunks up to block size
        for block_index in range(0, len(plaintext), self.block_size):
            block = plaintext[block_index:block_index + self.block_size]

            # Encrypt the previous block (IV for first iteration) to create keystream
            encrypted_iv = self.cipher.encrypt_block(previous_block)

            # Truncate keystream to match current block length
            truncated = encrypted_iv[:len(block)]

            # XOR plaintext block with keystream
            cipher_block = bytes(a ^ b for a, b in zip(block, truncated))

            ciphertext.extend(cipher_block)

            # For CFB mode, next previous_block is the current ciphertext block
            # If block is shorter than block_size, pad it for the shift register
            if len(cipher_block) < self.block_size:
                previous_block = previous_block[len(cipher_block):] + cipher_block
            else:
                previous_block = cipher_block

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using CFB mode.

        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (must be block_size bytes)

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If IV length doesn't match block size
        """
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes.")

        plaintext = bytearray()
        previous_block = iv

        # Process data in chunks up to block size
        for block_index in range(0, len(ciphertext), self.block_size):
            block = ciphertext[block_index:block_index + self.block_size]

            # Encrypt the previous block (IV for first iteration) to create keystream
            encrypted_iv = self.cipher.encrypt_block(previous_block)

            # Truncate keystream to match current block length
            truncated = encrypted_iv[:len(block)]

            # XOR ciphertext block with keystream to get plaintext
            plain_block = bytes(a ^ b for a, b in zip(block, truncated))

            plaintext.extend(plain_block)

            # For CFB mode, next previous_block is the current ciphertext block
            # If block is shorter than block_size, pad it for the shift register
            if len(block) < self.block_size:
                previous_block = previous_block[len(block):] + block
            else:
                previous_block = block

        return bytes(plaintext)