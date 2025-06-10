"""
Electronic Codebook (ECB) Mode

ECB is the simplest block cipher mode where each block is encrypted independently.
WARNING: ECB mode is not semantically secure and should not be used in practice
for encrypting data with patterns, as identical plaintext blocks produce identical
ciphertext blocks.
"""

from katcrypt.utils import pkcs7_pad, pkcs7_unpad


class ECB:
    """
    Electronic Codebook (ECB) mode of operation.

    In ECB mode, each plaintext block is encrypted independently:
    C[i] = E(K, P[i])

    This mode is included for educational purposes to demonstrate why
    simple block-by-block encryption is insufficient for most applications.
    """

    def __init__(self, cipher):
        """
        Initialize ECB mode with a block cipher.

        Args:
            cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
        """
        self.cipher = cipher
        self.block_size = cipher.block_size

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using ECB mode.

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted ciphertext
        """
        # Apply PKCS#7 padding to make plaintext a multiple of block size
        padded = pkcs7_pad(plaintext, self.block_size)

        ciphertext = bytearray()

        # Encrypt each block independently
        for block_index in range(0, len(padded), self.block_size):
            block = padded[block_index:block_index + self.block_size]
            encrypted_block = self.cipher.encrypt_block(block)
            ciphertext.extend(encrypted_block)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using ECB mode.

        Args:
            ciphertext: Data to decrypt

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If ciphertext length is not a multiple of block size
        """
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Ciphertext length must be a multiple of {self.block_size} bytes.")

        plaintext = bytearray()

        # Decrypt each block independently
        for block_index in range(0, len(ciphertext), self.block_size):
            block = ciphertext[block_index:block_index + self.block_size]
            decrypted_block = self.cipher.decrypt_block(block)
            plaintext.extend(decrypted_block)

        # Remove PKCS#7 padding
        return pkcs7_unpad(bytes(plaintext))