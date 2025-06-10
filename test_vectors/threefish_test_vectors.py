from katcrypt.ciphers.threefish import Threefish

# Test vectors from official sources
def run_test_vectors():
    """Test against official Threefish test vectors"""
    print("Running Threefish test vectors...")

    # Test Vector 1: From CryptoPP test vectors (these use big-endian output format)
    print("\n=== Test Vector 1: Threefish-256 (all zeros) ===")
    key = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    tweak = bytes.fromhex('00000000000000000000000000000000')
    plaintext = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    expected = bytes.fromhex('94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11')

    cipher = Threefish(key, tweak)
    ciphertext = cipher.encrypt_block(plaintext)

    print(f"Key:       {key.hex().upper()}")
    print(f"Tweak:     {tweak.hex().upper()}")
    print(f"Plaintext: {plaintext.hex().upper()}")
    print(f"Expected:  {expected.hex().upper()}")
    print(f"Got:       {ciphertext.hex().upper()}")
    print(f"PASS:      {ciphertext == expected}")

    # Test decryption
    decrypted = cipher.decrypt_block(ciphertext)
    print(f"Decrypted: {decrypted.hex().upper()}")
    print(f"Decrypt OK: {decrypted == plaintext}")

    # Test Vector 2: From CryptoPP test vectors
    print("\n=== Test Vector 2: Threefish-256 with non-zero key/tweak ===")
    key = bytes.fromhex('17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A2928')
    tweak = bytes.fromhex('07060504030201000F0E0D0C0B0A0908')
    plaintext = bytes.fromhex('F8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7')
    expected = bytes.fromhex('DF8FEA0EFF91D0E0D50AD82EE69281C976F48D58085D869DDF975E95B5567065')

    cipher = Threefish(key, tweak)
    ciphertext = cipher.encrypt_block(plaintext)

    print(f"Key:       {key.hex().upper()}")
    print(f"Tweak:     {tweak.hex().upper()}")
    print(f"Plaintext: {plaintext.hex().upper()}")
    print(f"Expected:  {expected.hex().upper()}")
    print(f"Got:       {ciphertext.hex().upper()}")
    print(f"PASS:      {ciphertext == expected}")

    # Test decryption
    decrypted = cipher.decrypt_block(ciphertext)
    print(f"Decrypted: {decrypted.hex().upper()}")
    print(f"Decrypt OK: {decrypted == plaintext}")

    # Test 512-bit functionality
    print("\n=== Test Threefish-512 basic functionality ===")
    key_512 = b'0' * 64  # 512-bit key
    tweak_512 = b'1' * 16  # 128-bit tweak
    plaintext_512 = b'Hello, World! This is a test of Threefish-512 encryption algorithm!!'[:64]
    plaintext_512 += b'\x00' * (64 - len(plaintext_512))  # Pad to 64 bytes

    cipher_512 = Threefish(key_512, tweak_512)
    encrypted_512 = cipher_512.encrypt_block(plaintext_512)
    decrypted_512 = cipher_512.decrypt_block(encrypted_512)

    print(f"Plaintext:  {plaintext_512.hex()}")
    print(f"Encrypted:  {encrypted_512.hex()}")
    print(f"Decrypted:  {decrypted_512.hex()}")
    print(f"Round-trip: {plaintext_512 == decrypted_512}")

    # Test 1024-bit functionality
    print("\n=== Test Threefish-1024 basic functionality ===")
    key_1024 = b'0' * 128  # 1024-bit key
    tweak_1024 = b'1' * 16  # 128-bit tweak
    plaintext_1024 = b'A' * 128  # 1024-bit block

    cipher_1024 = Threefish(key_1024, tweak_1024)
    encrypted_1024 = cipher_1024.encrypt_block(plaintext_1024)
    decrypted_1024 = cipher_1024.decrypt_block(encrypted_1024)

    print(f"1024-bit round-trip: {plaintext_1024 == decrypted_1024}")

    # Verify against reference implementation for 256-bit
    print("\n=== Reference Implementation Comparison ===")

    # Pierre de Buyl's reference for all-zeros
    ref_key = (0x0, 0x0, 0x0, 0x0)
    ref_tweak = (0x0, 0x0)
    ref_plain = (0x0, 0x0, 0x0, 0x0)

    # Expected output words from reference: [0x94eeea8b1f2ada84, 0xadf103313eae6670, 0x952419a1f4b16d53, 0xd83f13e63c9f6b11]
    # As bytes in big-endian: 94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11

    ref_expected = bytes.fromhex('94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11')

    cipher_ref = Threefish(bytes(32), bytes(16))
    ref_result = cipher_ref.encrypt_block(bytes(32))

    print(f"Reference expected: {ref_expected.hex().upper()}")
    print(f"Our result:         {ref_result.hex().upper()}")
    print(f"Match reference:    {ref_result == ref_expected}")

    return True


# Example usage
if __name__ == "__main__":
    run_test_vectors()

    print("\n" + "=" * 50)
    print("Basic functionality test:")

    # Test with pattern data
    key = b'0123456789ABCDEF' * 2  # 256-bit key
    tweak = b'FEDCBA9876543210'  # 128-bit tweak

    cipher = Threefish(key, tweak)

    # Test encryption/decryption
    plaintext = b'Hello, Threefish!' + b'\x00' * 15  # Pad to 32 bytes
    print(f"Original:  {plaintext.hex()}")

    ciphertext = cipher.encrypt_block(plaintext)
    print(f"Encrypted: {ciphertext.hex()}")

    decrypted = cipher.decrypt_block(ciphertext)
    print(f"Decrypted: {decrypted.hex()}")

    print(f"Success: {plaintext == decrypted}")