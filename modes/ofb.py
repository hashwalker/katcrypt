"""
Output Feedback (OFB) Mode

OFB is a block cipher mode that operates like a stream cipher. The block cipher
encrypts the initialization vector (or previous keystream block) to produce
a keystream, which is then XORed with the plaintext. Unlike CFB, OFB uses the
keystream output as feedback, not the ciphertext, making encryption and decryption
identical operations.
"""

from katcrypt.utils import pkcs7_pad, pkcs7_unpad


class OFB:
   """
   Output Feedback (OFB) mode of operation.

   In OFB mode, the block cipher encrypts the previous keystream block (or IV)
   to create the next keystream block that is XORed with the plaintext:
   K[0] = E(K, IV)
   K[i] = E(K, K[i-1]) for i > 0
   C[i] = P[i] ⊕ K[i]

   OFB mode turns a block cipher into a stream cipher and does not require padding.
   Encryption and decryption are identical operations.
   """

   def __init__(self, cipher):
       """
       Initialize OFB mode with a block cipher.

       Args:
           cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
       """
       self.cipher = cipher
       self.block_size = cipher.block_size

   def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
       """
       Encrypt plaintext using OFB mode.

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
       feedback = iv

       # Process data in chunks up to block size
       for block_index in range(0, len(plaintext), self.block_size):
           block = plaintext[block_index:block_index + self.block_size]

           # Generate keystream by encrypting the feedback
           keystream = self.cipher.encrypt_block(feedback)

           # Truncate keystream to match current block length
           keystream_truncated = keystream[:len(block)]

           # XOR plaintext block with keystream
           cipher_block = bytes(a ^ b for a, b in zip(block, keystream_truncated))
           ciphertext.extend(cipher_block)

           # For OFB mode, feedback is always the full keystream block
           feedback = keystream

       return bytes(ciphertext)

   def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
       """
       Decrypt ciphertext using OFB mode.

       In OFB mode, decryption is identical to encryption since we XOR
       with the same keystream.

       Args:
           ciphertext: Data to decrypt
           iv: Initialization vector (must be block_size bytes)

       Returns:
           Decrypted plaintext

       Raises:
           ValueError: If IV length doesn't match block size
       """
       return self.encrypt(ciphertext, iv)