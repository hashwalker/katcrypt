def get_supported_algorithms():
    return {
        "block_ciphers": ["AES", "MARS", "Threefish"],
        "modes": ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"],
    }
