"""
Cipher Block Chaining (CBC) Mode

CBC is a block cipher mode where each plaintext block is XORed with the previous
ciphertext block before encryption. The first block is XORed with an initialization
vector (IV). This creates a dependency between blocks, making the mode semantically
secure when used with a random IV.
"""

from katcrypt.utils import pkcs7_pad, pkcs7_unpad


class CBC:
   """
   Cipher Block Chaining (CBC) mode of operation.

   In CBC mode, each plaintext block is XORed with the previous ciphertext block:
   C[0] = E(K, P[0] ⊕ IV)
   C[i] = E(K, P[i] ⊕ C[i-1]) for i > 0

   This mode provides semantic security when used with a random IV.
   """

   def __init__(self, cipher):
       """
       Initialize CBC mode with a block cipher.

       Args:
           cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
       """
       self.cipher = cipher
       self.block_size = cipher.block_size

   def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
       """
       Encrypt plaintext using CBC mode.

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

       # Apply PKCS#7 padding to make plaintext a multiple of block size
       padded = pkcs7_pad(plaintext, self.block_size)

       previous_block = iv
       ciphertext = bytearray()

       # Encrypt each block after XORing with previous ciphertext block
       for block_index in range(0, len(padded), self.block_size):
           block = padded[block_index:block_index + self.block_size]

           # XOR current block with previous ciphertext block (or IV for first block)
           xored = bytes(a ^ b for a, b in zip(block, previous_block))

           # Encrypt the XORed block
           encrypted_block = self.cipher.encrypt_block(xored)

           ciphertext.extend(encrypted_block)
           previous_block = encrypted_block

       return bytes(ciphertext)

   def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
       """
       Decrypt ciphertext using CBC mode.

       Args:
           ciphertext: Data to decrypt
           iv: Initialization vector (must be block_size bytes)

       Returns:
           Decrypted plaintext

       Raises:
           ValueError: If IV length doesn't match block size or ciphertext
                      length is not a multiple of block size
       """
       if len(iv) != self.block_size:
           raise ValueError(f"IV must be {self.block_size} bytes.")
       if len(ciphertext) % self.block_size != 0:
           raise ValueError(f"Ciphertext length must be a multiple of {self.block_size} bytes.")

       previous_block = iv
       plaintext = bytearray()

       # Decrypt each block and XOR with previous ciphertext block
       for block_index in range(0, len(ciphertext), self.block_size):
           block = ciphertext[block_index:block_index + self.block_size]

           # Decrypt the current block
           decrypted_block = self.cipher.decrypt_block(block)

           # XOR with previous ciphertext block (or IV for first block)
           xored = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))

           plaintext.extend(xored)
           previous_block = block

       # Remove PKCS#7 padding
       return pkcs7_unpad(bytes(plaintext))