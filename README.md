# KatCrypt

A pure Python cryptographic library implementing multiple block ciphers and encryption modes from scratch.

## Overview

KatCrypt provides implementations of modern block ciphers and standard modes of operation, built entirely in Python without external cryptographic dependencies. All algorithms are implemented from their original specifications with comprehensive test vector validation.

## Supported Algorithms

### Block Ciphers
- **AES (Advanced Encryption Standard)** - 128, 192, and 256-bit keys
- **MARS** - IBM's AES competition finalist 
- **Threefish** - Block cipher from the Skein hash function family

### Modes of Operation
- ECB (Electronic Code Book)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback) 
- CTR (Counter Mode)
- GCM (Galois/Counter Mode with authentication)

## Installation

### From Source
```bash
git clone https://github.com/hashwalker/katcrypt.git
cd katcrypt
pip install -e .
```

### Requirements
- Python 3.7+
- No external dependencies

## Usage

### Functional API
```python
import katcrypt
from katcrypt.utils import generate_key, generate_iv

# Basic encryption example
key = generate_key(256)  # 256-bit key for AES
iv = generate_iv(16)     # 128-bit IV
plaintext = b"Hello, World! This is a secret message."

print(f"Original: {plaintext}")

# Encrypt the message
ciphertext = katcrypt.encrypt(
    cipher="aes", 
    mode="cbc", 
    key=key, 
    plaintext=plaintext, 
    iv=iv
)

print(f"Encrypted: {ciphertext.hex()}")

# Decrypt the message
decrypted = katcrypt.decrypt(
    cipher="aes", 
    mode="cbc", 
    key=key, 
    ciphertext=ciphertext, 
    iv=iv
)

print(f"Decrypted: {decrypted}")
print(f"Success: {plaintext == decrypted}")
```

### Object-Oriented API
```python
from katcrypt.ciphers.aes import AES
from katcrypt.modes.cbc import CBC
from katcrypt.utils import generate_key, generate_iv

# Setup
key = generate_key(256)
iv = generate_iv(16)
plaintext = b"Object-oriented encryption example!"

print(f"Original: {plaintext}")

# Create cipher and mode objects
cipher = AES(key=key)
mode = CBC(cipher)

# Encrypt and decrypt
ciphertext = mode.encrypt(plaintext, iv)
print(f"Encrypted: {ciphertext.hex()}")

decrypted = mode.decrypt(ciphertext, iv)
print(f"Decrypted: {decrypted}")
print(f"Success: {plaintext == decrypted}")
```

## Project Structure
```
katcrypt/
├── ciphers/             # Block cipher implementations
├── modes/               # Mode of operation implementations  
├── utils.py             # Cryptographic utilities
├── constants/           # Algorithm constants and tables
└── test_vectors/        # Test vectors and validation
```

## Testing

The library includes comprehensive test vectors from official sources:

```bash
python test_vectors/aes_test_vectors.py
python test_vectors/mars_test_vectors.py  
python test_vectors/threefish_test_vectors.py
```

Test vectors validate against:
- NIST AES test vectors
- IBM MARS reference implementation
- Threefish reference vectors

## Security Notice

**This library is intended for educational and research purposes only.** 

It is not suitable for production use as it lacks:
- Constant-time implementations
- Side-channel attack protections
- Formal security audits
- Timing attack mitigations

For production applications, use established libraries such as `cryptography` or `pycryptodome`.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Created by hashwalker

