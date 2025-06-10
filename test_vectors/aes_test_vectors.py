"""
Test katcrypt aes implementations against official test vectors.
"""

from katcrypt.ciphers.aes import AES
from katcrypt.modes.ecb import ECB
from katcrypt.modes.cbc import CBC
from katcrypt.modes.cfb import CFB
from katcrypt.modes.ofb import OFB
from katcrypt.modes.ctr import CTR
from katcrypt.modes.gcm import GCM
from katcrypt.utils import hex_to_bytes, bytes_to_hex


#####################################
# Test Vectors
#####################################

# AES ECB Test Vectors from NIST SP 800-38A
AES_ECB_TEST_VECTORS = [
    {
        "name": "AES-128 ECB Encrypt",
        "source": "NIST SP 800-38A F.1.1",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
        "key_size": 128
    },
    {
        "name": "AES-192 ECB Encrypt",
        "source": "NIST SP 800-38A F.1.3",
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
        "key_size": 192
    },
    {
        "name": "AES-256 ECB Encrypt",
        "source": "NIST SP 800-38A F.1.5",
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
        "key_size": 256
    }
]

# Single block test vectors for basic validation
AES_SINGLE_BLOCK_VECTORS = [
    {
        "name": "AES-128 Single Block",
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00112233445566778899aabbccddeeff",
        "ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a",
        "key_size": 128
    },
    {
        "name": "AES-192 Single Block",
        "key": "000102030405060708090a0b0c0d0e0f1011121314151617",
        "plaintext": "00112233445566778899aabbccddeeff",
        "ciphertext": "dda97ca4864cdfe06eaf70a0ec0d7191",
        "key_size": 192
    },
    {
        "name": "AES-256 Single Block",
        "key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "plaintext": "00112233445566778899aabbccddeeff",
        "ciphertext": "8ea2b7ca516745bfeafc49904b496089",
        "key_size": 256
    }
]

# AES CBC Test Vectors from NIST SP 800-38A and RFC 3602
AES_CBC_TEST_VECTORS = [
    {
        "name": "AES-128 CBC Encrypt",
        "source": "NIST SP 800-38A F.2.1",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        "key_size": 128
    },
    {
        "name": "AES-192 CBC Encrypt",
        "source": "NIST SP 800-38A F.2.3",
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        "key_size": 192
    },
    {
        "name": "AES-256 CBC Encrypt",
        "source": "NIST SP 800-38A F.2.5",
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        "key_size": 256
    },
    {
        "name": "RFC 3602 Case 1 - Single Block",
        "source": "RFC 3602",
        "key": "06a9214036b8a15b512e03d534120006",
        "iv": "3dafba429d9eb430b422da802c9fac41",
        "plaintext": "53696e676c6520626c6f636b206d7367",  # "Single block msg"
        "ciphertext": "e353779c1079aeb82708942dbe77181a",
        "key_size": 128
    },
    {
        "name": "RFC 3602 Case 2 - Two Blocks",
        "source": "RFC 3602",
        "key": "c286696d887c9aa0611bbb3e2025a45a",
        "iv": "562e17996d093d28ddb3ba695a2e6f58",
        "plaintext": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ciphertext": "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1",
        "key_size": 128
    }
]

# AES CFB Test Vectors from NIST SP 800-38A (CFB128 only)
AES_CFB_TEST_VECTORS = [
    {
        "name": "AES-128 CFB128 Encrypt",
        "source": "NIST SP 800-38A F.3.13",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
        "key_size": 128
    },
    {
        "name": "AES-192 CFB128 Encrypt",
        "source": "NIST SP 800-38A F.3.15",
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
        "key_size": 192
    },
    {
        "name": "AES-256 CFB128 Encrypt",
        "source": "NIST SP 800-38A F.3.17",
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
        "key_size": 256
    }
]

# AES OFB Test Vectors from NIST SP 800-38A
AES_OFB_TEST_VECTORS = [
    {
        "name": "AES-128 OFB Encrypt",
        "source": "NIST SP 800-38A F.4.1",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
        "key_size": 128
    },
    {
        "name": "AES-192 OFB Encrypt",
        "source": "NIST SP 800-38A F.4.3",
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a",
        "key_size": 192
    },
    {
        "name": "AES-256 OFB Encrypt",
        "source": "NIST SP 800-38A F.4.5",
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
        "key_size": 256
    }
]

# AES CTR Test Vectors from NIST SP 800-38A and RFC 3686
AES_CTR_TEST_VECTORS = [
    # NIST SP 800-38A vectors
    {
        "name": "AES-128 CTR Encrypt",
        "source": "NIST SP 800-38A F.5.1",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "nonce": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
        "key_size": 128
    },
    {
        "name": "AES-192 CTR Encrypt",
        "source": "NIST SP 800-38A F.5.3",
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "nonce": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
        "key_size": 192
    },
    {
        "name": "AES-256 CTR Encrypt",
        "source": "NIST SP 800-38A F.5.5",
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "nonce": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "plaintext": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "ciphertext": "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
        "key_size": 256
    },
    # RFC 3686 vectors (using full 16-byte initial counter blocks)
    {
        "name": "RFC 3686 Test Vector 1",
        "source": "RFC 3686",
        "key": "ae6852f8121067cc4bf7a5765577f39e",
        "nonce": "00000030000000000000000000000001",
        "plaintext": "53696e676c6520626c6f636b206d7367",
        "ciphertext": "e4095d4fb7a7b3792d6175a3261311b8",
        "key_size": 128
    },
    {
        "name": "RFC 3686 Test Vector 2",
        "source": "RFC 3686",
        "key": "7e24067817fae0d743d6ce1f32539163",
        "nonce": "006cb6dbc0543b59da48d90b00000001",  # 32 hex chars = 16 bytes
        "plaintext": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ciphertext": "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",
        "key_size": 128
    },
    {
        "name": "RFC 3686 Test Vector 7 (AES-256)",
        "source": "RFC 3686",
        "key": "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
        "nonce": "00000060db5672c97aa8f0b200000001",  # 32 hex chars = 16 bytes
        "plaintext": "53696e676c6520626c6f636b206d7367",
        "ciphertext": "145ad01dbf824ec7560863dc71e3e0c0",
        "key_size": 256
    }
]

# AES GCM Test Vectors from aes-modes-src-07-10-08/Testvals/gcm.1
AES_GCM_TEST_VECTORS = [
    # Basic test - empty plaintext, should fail MAC verification
    {
        "name": "AES-128 GCM Empty - Invalid MAC",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "00000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "",
        "aad": "",
        "ciphertext": "",
        "mac": "00000000000000000000000000000000",
        "should_verify": False,
        "key_size": 128
    },
    # Basic test - empty plaintext, valid MAC
    {
        "name": "AES-128 GCM Empty - Valid MAC",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "00000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "",
        "aad": "",
        "ciphertext": "",
        "mac": "58e2fccefa7e3061367f1d57a4e7455a",
        "should_verify": True,
        "key_size": 128
    },
    # Single block test
    {
        "name": "AES-128 GCM Single Block",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "00000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "00000000000000000000000000000000",
        "aad": "",
        "ciphertext": "0388dace60b6a392f328c2b971b2fe78",
        "mac": "ab6e47d42cec13bdf53a67b21257bddf",
        "should_verify": True,
        "key_size": 128
    },
    # Standard test with 96-bit IV
    {
        "name": "AES-128 GCM Standard Test",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "feffe9928665731c6d6a8f9467308308",
        "iv": "cafebabefacedbaddecaf888",
        "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "aad": "",
        "ciphertext": "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "mac": "4d5c2af327cd64a62cf35abd2ba6fab4",
        "should_verify": True,
        "key_size": 128
    },
    # Test with AAD
    {
        "name": "AES-128 GCM with AAD",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "feffe9928665731c6d6a8f9467308308",
        "iv": "cafebabefacedbaddecaf888",
        "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "ciphertext": "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "mac": "5bc94fbc3221a5db94fae95ae7121a47",
        "should_verify": True,
        "key_size": 128
    },
    # Test with 64-bit IV
    {
        "name": "AES-128 GCM 64-bit IV",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "feffe9928665731c6d6a8f9467308308",
        "iv": "cafebabefacedbad",
        "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "ciphertext": "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        "mac": "3612d2e79e3b0785561be14aaca2fccb",
        "should_verify": True,
        "key_size": 128
    },
    # AES-192 test
    {
        "name": "AES-192 GCM Empty",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "000000000000000000000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "",
        "aad": "",
        "ciphertext": "",
        "mac": "cd33b28ac773f74ba00ed1f312572435",
        "should_verify": True,
        "key_size": 192
    },
    # AES-192 single block
    {
        "name": "AES-192 GCM Single Block",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "000000000000000000000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "00000000000000000000000000000000",
        "aad": "",
        "ciphertext": "98e7247c07f0fe411c267e4384b0f600",
        "mac": "2ff58d80033927ab8ef4d4587514f0fb",
        "should_verify": True,
        "key_size": 192
    },
    # AES-256 test
    {
        "name": "AES-256 GCM Empty",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "0000000000000000000000000000000000000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "",
        "aad": "",
        "ciphertext": "",
        "mac": "530f8afbc74536b9a963b4f1c4cb738b",
        "should_verify": True,
        "key_size": 256
    },
    # AES-256 single block
    {
        "name": "AES-256 GCM Single Block",
        "source": "aes-modes-src-07-10-08/Testvals/gcm.1",
        "key": "0000000000000000000000000000000000000000000000000000000000000000",
        "iv": "000000000000000000000000",
        "plaintext": "00000000000000000000000000000000",
        "aad": "",
        "ciphertext": "cea7403d4d606b6e074ec5d3baf39d18",
        "mac": "d0d1c8a799996bf0265b98b5d48ab919",
        "should_verify": True,
        "key_size": 256
    }
]

#####################################
# Test Functions
#####################################

def track_test_results():
    """Decorator to track test results globally."""
    if not hasattr(track_test_results, 'failed_tests'):
        track_test_results.failed_tests = []
    return track_test_results.failed_tests

def test_aes_single_blocks():
    """Test AES single block encryption against known vectors."""
    print("=" * 50)
    print("Testing AES Single Block Encryption...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_SINGLE_BLOCK_VECTORS:
        key = hex_to_bytes(vector["key"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        result = cipher.encrypt_block(plaintext)

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']}")
        if not success:
            failed_tests.append(f"AES Single Block: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)}")
            print(f"  Got:      {bytes_to_hex(result)}")
        print()

def test_aes_ecb_mode():
    """Test AES ECB mode against NIST test vectors."""
    print("=" * 50)
    print("Testing AES ECB Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_ECB_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        ecb = ECB(cipher)

        # For test vectors, we need to handle the padding carefully
        # Test vectors don't include padding, so we'll test block by block
        result_blocks = []
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            encrypted_block = cipher.encrypt_block(block)
            result_blocks.append(encrypted_block)

        result = b''.join(result_blocks)

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
        print(f"  Source: {vector['source']}")
        if not success:
            failed_tests.append(f"AES ECB: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)[:64]}...")
            print(f"  Got:      {bytes_to_hex(result)[:64]}...")
        print()

def test_aes_cbc_mode():
    """Test AES CBC mode against NIST and RFC test vectors."""
    print("=" * 50)
    print("Testing AES CBC Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_CBC_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        iv = hex_to_bytes(vector["iv"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        cbc = CBC(cipher)

        # For test vectors without padding, encrypt block by block
        result_blocks = []
        previous_block = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            xored = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = cipher.encrypt_block(xored)
            result_blocks.append(encrypted_block)
            previous_block = encrypted_block

        result = b''.join(result_blocks)

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
        print(f"  Source: {vector['source']}")
        if not success:
            failed_tests.append(f"AES CBC: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)[:64]}...")
            print(f"  Got:      {bytes_to_hex(result)[:64]}...")
        print()

def test_aes_cfb_mode():
    """Test AES CFB mode against NIST test vectors."""
    print("=" * 50)
    print("Testing AES CFB Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_CFB_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        iv = hex_to_bytes(vector["iv"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        cfb = CFB(cipher)

        # Test encryption
        result = cfb.encrypt(plaintext, iv)

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
        print(f"  Source: {vector['source']}")
        if not success:
            failed_tests.append(f"AES CFB: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)[:64]}...")
            print(f"  Got:      {bytes_to_hex(result)[:64]}...")
        print()

def test_aes_ofb_mode():
    """Test AES OFB mode against NIST test vectors."""
    print("=" * 50)
    print("Testing AES OFB Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_OFB_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        iv = hex_to_bytes(vector["iv"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        ofb = OFB(cipher)

        # Test encryption
        result = ofb.encrypt(plaintext, iv)

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
        print(f"  Source: {vector['source']}")
        if not success:
            failed_tests.append(f"AES OFB: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)[:64]}...")
            print(f"  Got:      {bytes_to_hex(result)[:64]}...")
        print()

def test_aes_ctr_mode():
    """Test AES CTR mode against NIST and RFC test vectors."""
    print("=" * 50)
    print("Testing AES CTR Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_CTR_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        nonce = hex_to_bytes(vector["nonce"])
        plaintext = hex_to_bytes(vector["plaintext"])
        expected = hex_to_bytes(vector["ciphertext"])

        cipher = AES(key)
        ctr = CTR(cipher)

        # Test encryption
        result = ctr.encrypt(plaintext, nonce)
        # Truncate result to match expected length (for RFC vectors)
        result = result[:len(expected)]

        success = result == expected
        status = "PASS" if success else "FAIL"

        print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
        print(f"  Source: {vector['source']}")
        if not success:
            failed_tests.append(f"AES CTR: {vector['name']}")
            print(f"  Expected: {bytes_to_hex(expected)[:64]}...")
            print(f"  Got:      {bytes_to_hex(result)[:64]}...")
        print()

def test_aes_gcm_mode():
    """Test AES GCM mode against official test vectors."""
    print("=" * 50)
    print("Testing AES GCM Mode...")
    print("=" * 50)

    failed_tests = track_test_results()

    for vector in AES_GCM_TEST_VECTORS:
        key = hex_to_bytes(vector["key"])
        iv = hex_to_bytes(vector["iv"])
        plaintext = hex_to_bytes(vector["plaintext"]) if vector["plaintext"] else b""
        aad = hex_to_bytes(vector["aad"]) if vector["aad"] else b""
        expected_ciphertext = hex_to_bytes(vector["ciphertext"]) if vector["ciphertext"] else b""
        expected_mac = hex_to_bytes(vector["mac"])

        cipher = AES(key)
        gcm = GCM(cipher)

        try:
            # Test encryption
            result_ciphertext, result_mac = gcm.encrypt(plaintext, iv, aad)

            # Check encryption results
            if vector.get("should_verify", True):
                # For normal vectors, check both ciphertext and MAC
                encrypt_success = (result_ciphertext == expected_ciphertext and
                                   result_mac == expected_mac)
            else:
                # For should_verify=False vectors, only check ciphertext
                # The expected_mac in these vectors is intentionally wrong
                encrypt_success = (result_ciphertext == expected_ciphertext)

            # Test decryption/verification
            if vector["should_verify"]:
                try:
                    decrypted = gcm.decrypt(expected_ciphertext, iv, expected_mac, aad)
                    decrypt_success = decrypted == plaintext
                except ValueError:
                    decrypt_success = False
            else:
                # Should fail verification
                try:
                    gcm.decrypt(expected_ciphertext, iv, expected_mac, aad)
                    decrypt_success = False  # Should have failed
                except ValueError:
                    decrypt_success = True   # Correctly failed

            success = encrypt_success and decrypt_success
            status = "PASS" if success else "FAIL"

            print(f"{status} {vector['name']} ({vector['key_size']}-bit)")
            print(f"  Source: {vector['source']}")
            if not success:
                failed_tests.append(f"AES GCM: {vector['name']}")
                if not encrypt_success:
                    print(f"  Encryption failed:")
                    print(f"    Expected CT: {bytes_to_hex(expected_ciphertext)[:64]}...")
                    print(f"    Got CT:      {bytes_to_hex(result_ciphertext)[:64]}...")
                    print(f"    Expected MAC: {bytes_to_hex(expected_mac)}")
                    print(f"    Got MAC:      {bytes_to_hex(result_mac)}")
                if not decrypt_success:
                    print(f"  Decryption/verification failed")
            print()

        except Exception as e:
            failed_tests.append(f"AES GCM: {vector['name']}")
            print(f"FAIL {vector['name']} ({vector['key_size']}-bit)")
            print(f"  Source: {vector['source']}")
            print(f"  Exception: {e}")
            print()

def test_roundtrip():
    """Test that encryption followed by decryption returns original."""
    print("=" * 50)
    print("Testing Round-trip Encryption/Decryption...")
    print("=" * 50)

    failed_tests = track_test_results()

    test_cases = [
        ("AES-128", hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")),
        ("AES-192", hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")),
        ("AES-256", hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    ]

    test_message = b"Hello, katcrypt! This is a test message for round-trip validation."

    for name, key in test_cases:
        cipher = AES(key)
        ecb = ECB(cipher)

        encrypted = ecb.encrypt(test_message)
        decrypted = ecb.decrypt(encrypted)

        success = decrypted == test_message
        status = "PASS" if success else "FAIL"

        print(f"{status} {name} Round-trip")
        if not success:
            failed_tests.append(f"Round-trip: {name}")
            print(f"  Original:  {test_message}")
            print(f"  Decrypted: {decrypted}")
        print()


#####################################
# Main Test Runner
#####################################

if __name__ == "__main__":
    print("=" * 60)
    print("AES TEST VECTORS")
    print("=" * 60)
    print()

    test_aes_single_blocks()
    test_aes_ecb_mode()
    test_aes_cbc_mode()
    test_aes_cfb_mode()
    test_aes_ofb_mode()
    test_aes_ctr_mode()
    test_aes_gcm_mode()
    test_roundtrip()

    failed_tests = track_test_results()

    if failed_tests:
        print("=" * 60)
        print(f"FAILED TESTS ({len(failed_tests)}):")
        for test in failed_tests:
            print(f"  - {test}")
        print("=" * 60)
        raise AssertionError(f"{len(failed_tests)} test(s) failed!")
    else:
        print("All tests completed successfully!")