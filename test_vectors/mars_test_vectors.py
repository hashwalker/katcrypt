from katcrypt.ciphers.mars import MARS

# Test Vector 1 - All Zeros
KEY = bytes.fromhex("00000000000000000000000000000000")  # 16 bytes (128-bit)
PLAINTEXT = bytes.fromhex("00000000000000000000000000000000")  # 16 bytes
EXPECTED_CIPHERTEXT = bytes.fromhex("DCC07B8DFB0738D6E30A22DFCF27E886")

mars = MARS(KEY)
ciphertext = mars.encrypt_block(PLAINTEXT)
print(f"Key:        {KEY.hex()}")
print(f"Plaintext:  {PLAINTEXT.hex()}")
print(f"Got:        {ciphertext.hex().upper()}")
print(f"Expected:   {EXPECTED_CIPHERTEXT.hex().upper()}")
print(f"Match:      {ciphertext.hex().upper() == EXPECTED_CIPHERTEXT.hex().upper()}")