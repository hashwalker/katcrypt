"""
Counter (CTR) Mode

CTR is a block cipher mode that operates like a stream cipher. The block cipher
encrypts a counter value to produce a keystream, which is then XORed with the
plaintext. The counter is typically composed of a nonce and a counter value.
CTR mode turns a block cipher into a stream cipher and does not require padding.
Encryption and decryption are identical operations.
"""

from katcrypt.utils import pkcs7_pad, pkcs7_unpad


class CTR:
   """
   Counter (CTR) mode of operation.

   In CTR mode, the block cipher encrypts a counter value to create
   a keystream that is XORed with the plaintext:
   CTR[i] = Nonce || Counter[i]
   K[i] = E(K, CTR[i])
   C[i] = P[i] ⊕ K[i]

   CTR mode turns a block cipher into a stream cipher and does not require padding.
   Encryption and decryption are identical operations.
   """

   def __init__(self, cipher):
       """
       Initialize CTR mode with a block cipher.

       Args:
           cipher: An instance of a block cipher (AES, MARS, Serpent, etc.)
       """
       self.cipher = cipher
       self.block_size = cipher.block_size

   def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
       """
       Encrypt plaintext using CTR mode.

       Args:
           plaintext: Data to encrypt
           nonce: Nonce/IV (must be block_size bytes for full counter or block_size//2 bytes for nonce+counter)

       Returns:
           Encrypted ciphertext

       Raises:
           ValueError: If nonce length is not block_size//2 or block_size bytes
       """
       n = len(nonce)
       half_block = self.block_size // 2
       if n not in (half_block, self.block_size):
           raise ValueError(f"Nonce must be either {half_block} or {self.block_size} bytes.")

       ciphertext = bytearray()
       block_count = (len(plaintext) + self.block_size - 1) // self.block_size

       # Handle full block size nonce (treat as initial counter value)
       if n == self.block_size:
           initial_ctr = int.from_bytes(nonce, "big")

       for block_idx in range(block_count):
           # Generate counter block
           if n == half_block:
               # Half-block nonce + half-block counter
               ctr_bytes = block_idx.to_bytes(half_block, "big")
               counter_block = nonce + ctr_bytes
           else:
               # Full block size counter (increment the entire value)
               current = (initial_ctr + block_idx) & ((1 << (self.block_size * 8)) - 1)
               counter_block = current.to_bytes(self.block_size, "big")

           # Generate keystream by encrypting counter
           keystream = self.cipher.encrypt_block(counter_block)

           # XOR plaintext chunk with keystream
           start = block_idx * self.block_size
           chunk = plaintext[start:start + self.block_size]
           cipher_chunk = bytes(data_byte ^ keystream_byte
                                for data_byte, keystream_byte in zip(chunk, keystream))
           ciphertext.extend(cipher_chunk)

       return bytes(ciphertext)

   def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
       """
       Decrypt ciphertext using CTR mode.

       In CTR mode, decryption is identical to encryption since we XOR
       with the same keystream.

       Args:
           ciphertext: Data to decrypt
           nonce: Nonce/IV (must be block_size bytes for full counter or block_size//2 bytes for nonce+counter)

       Returns:
           Decrypted plaintext

       Raises:
           ValueError: If nonce length is not block_size//2 or block_size bytes
       """
       return self.encrypt(ciphertext, nonce)