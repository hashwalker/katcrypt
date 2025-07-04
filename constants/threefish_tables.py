# === Threefish Cipher Constants ===

# Threefish universal constant (C240)
C240 = 0x1BD11BDAA9FC1A22

# Rotation constants for different block sizes
ROTATION_CONSTANTS = {
    4: (    # 256-bit (4 words)
        (14, 16), (52, 57), (23, 40), (5, 37),
        (25, 33), (46, 12), (58, 22), (32, 32)
    ),
    8: [    # 512-bit (8 words)
        [46, 36, 19, 37], [33, 27, 14, 42], [17, 49, 36, 39], [44, 9, 54, 56],
        [39, 30, 34, 24], [13, 50, 10, 17], [25, 29, 39, 43], [8, 35, 56, 22]
    ],
    16: [   # 1024-bit (16 words)
        [24, 13, 8, 47, 8, 17, 22, 37], [38, 19, 10, 55, 49, 18, 23, 52],
        [33, 4, 51, 13, 34, 41, 59, 17], [5, 20, 48, 41, 47, 28, 16, 25],
        [41, 9, 37, 31, 12, 47, 44, 30], [16, 34, 56, 51, 4, 53, 42, 41],
        [31, 44, 47, 46, 19, 42, 44, 25], [9, 48, 35, 52, 23, 31, 37, 20]
    ]
}