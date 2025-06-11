"""
KatCrypt - A unified cryptographic library supporting AES, MARS and Threefish ciphers
with multiple modes of operation.

"""

__version__ = "0.1.4"
__author__ = "Hashwalker"

# Supported algorithms for reference
SUPPORTED_CIPHERS = ['aes', 'mars', 'threefish']
SUPPORTED_MODES = ['cbc', 'cfb', 'ctr', 'ecb', 'gcm', 'ofb']
