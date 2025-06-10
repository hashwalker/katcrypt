# === Threefish Cipher in Python - Fixed Implementation ===
from katcrypt.constants.threefish_tables import C240, ROTATION_CONSTANTS

class Threefish:
    def __init__(self, key: bytes, tweak: bytes = None):
        self.key = key
        self.key_length = len(key)
        self.tweak = tweak or b'\x00' * 16

        if self.key_length == 32:  # 256-bit
            self.words = 4
            self.rounds = 72
        elif self.key_length == 64:  # 512-bit
            self.words = 8
            self.rounds = 72
        elif self.key_length == 128:  # 1024-bit
            self.words = 16
            self.rounds = 80
        else:
            raise ValueError("Key must be 32, 64, or 128 bytes long (256, 512, or 1024 bits).")

        self.word_size = 64  # bits
        self.word_bytes = 8
        self.block_size = self.words * self.word_bytes

        # Threefish constant
        self.C240 = C240

        # Rotation constants for each block size
        self._init_rotation_constants()

        # Generate subkeys
        self.subkeys = []
        self._generate_subkeys()

    def _init_rotation_constants(self):
        """Initialize rotation constants for different block sizes"""
        self.rotation_constants = ROTATION_CONSTANTS[self.words]

    def _bytes_to_words(self, data: bytes) -> list:
        """Convert bytes to 64-bit words (little-endian)"""
        words = []
        for i in range(0, len(data), 8):
            word = int.from_bytes(data[i:i + 8], byteorder='little')
            words.append(word)
        return words

    def _words_to_bytes(self, words: list) -> bytes:
        """Convert 64-bit words to bytes (big-endian for test vector compatibility)"""
        result = bytearray()
        for word in words:
            result.extend(word.to_bytes(8, byteorder='big'))
        return bytes(result)

    def _bytes_to_words_be(self, data: bytes) -> list:
        """Convert bytes to 64-bit words (big-endian)"""
        words = []
        for i in range(0, len(data), 8):
            word = int.from_bytes(data[i:i + 8], byteorder='big')
            words.append(word)
        return words

    def _words_to_bytes_le(self, words: list) -> bytes:
        """Convert 64-bit words to bytes (little-endian)"""
        result = bytearray()
        for word in words:
            result.extend(word.to_bytes(8, byteorder='little'))
        return bytes(result)

    def _add_mod_2_64(self, a: int, b: int) -> int:
        """Addition modulo 2^64"""
        return (a + b) & 0xFFFFFFFFFFFFFFFF

    def _sub_mod_2_64(self, a: int, b: int) -> int:
        """Subtraction modulo 2^64"""
        return (a - b) & 0xFFFFFFFFFFFFFFFF

    def _rotate_left(self, value: int, amount: int) -> int:
        """Rotate left by amount bits (64-bit word)"""
        amount %= 64
        return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF

    def _rotate_right(self, value: int, amount: int) -> int:
        """Rotate right by amount bits (64-bit word)"""
        amount %= 64
        return ((value >> amount) | (value << (64 - amount))) & 0xFFFFFFFFFFFFFFFF

    def _generate_subkeys(self):
        """Generate subkeys for all rounds"""
        # Convert key and tweak to words
        key_words = self._bytes_to_words(self.key)
        tweak_words = self._bytes_to_words(self.tweak)

        # Extend key with parity
        key_extended = list(key_words)
        parity = self.C240
        for word in key_words:
            parity ^= word
        key_extended.append(parity)

        # Extend tweak
        tweak_extended = list(tweak_words) + [tweak_words[0] ^ tweak_words[1]]

        # Generate subkeys
        num_subkeys = (self.rounds // 4) + 1
        for s in range(num_subkeys):
            subkey = []
            for i in range(self.words):
                if i < self.words - 3:
                    subkey.append(key_extended[(s + i) % (self.words + 1)])
                elif i == self.words - 3:
                    subkey.append(self._add_mod_2_64(
                        key_extended[(s + i) % (self.words + 1)],
                        tweak_extended[s % 3]
                    ))
                elif i == self.words - 2:
                    subkey.append(self._add_mod_2_64(
                        key_extended[(s + i) % (self.words + 1)],
                        tweak_extended[(s + 1) % 3]
                    ))
                else:  # i == self.words - 1
                    subkey.append(self._add_mod_2_64(
                        key_extended[(s + i) % (self.words + 1)],
                        s
                    ))
            self.subkeys.append(subkey)

    def _mix_function(self, x0: int, x1: int, rotation: int):
        """Threefish mix function"""
        y0 = self._add_mod_2_64(x0, x1)
        y1 = self._rotate_left(x1, rotation) ^ y0
        return y0, y1

    def _inv_mix_function(self, y0: int, y1: int, rotation: int):
        """Inverse Threefish mix function"""
        x1 = self._rotate_right(y1 ^ y0, rotation)
        x0 = self._sub_mod_2_64(y0, x1)
        return x0, x1

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single block"""
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes long")

        # Convert to words
        words = self._bytes_to_words(block)

        # Define permutation based on block size
        if self.words == 4:
            pi = (0, 3, 2, 1)
        elif self.words == 8:
            pi = (2, 1, 4, 7, 6, 5, 0, 3)
        elif self.words == 16:
            pi = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)

        # Process all rounds
        for round_num in range(self.rounds):
            # Add subkey every 4 rounds
            if round_num % 4 == 0:
                subkey_idx = round_num // 4
                subkey = self.subkeys[subkey_idx]
                for i in range(self.words):
                    words[i] = self._add_mod_2_64(words[i], subkey[i])

            # Mix function
            f = [0] * self.words
            round_const_idx = round_num % 8

            # Apply mix to pairs
            if self.words == 4:
                f[0], f[1] = self._mix_function(words[0], words[1], self.rotation_constants[round_const_idx][0])
                f[2], f[3] = self._mix_function(words[2], words[3], self.rotation_constants[round_const_idx][1])
            else:
                for i in range(0, self.words, 2):
                    pair_idx = i // 2
                    rotation = self.rotation_constants[round_const_idx][pair_idx]
                    f[i], f[i + 1] = self._mix_function(words[i], words[i + 1], rotation)

            # Apply permutation
            words = [f[pi[i]] for i in range(self.words)]

        # Final subkey addition
        final_subkey = self.subkeys[self.rounds // 4]
        for i in range(self.words):
            words[i] = self._add_mod_2_64(words[i], final_subkey[i])

        return self._words_to_bytes(words)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single block"""
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes long")

        # Convert to words - need to read as big-endian since output was big-endian
        words = self._bytes_to_words_be(block)

        # Define permutation and its inverse based on block size
        if self.words == 4:
            pi = (0, 3, 2, 1)
            inv_pi = (0, 3, 2, 1)  # Self-inverse
        elif self.words == 8:
            pi = (2, 1, 4, 7, 6, 5, 0, 3)
            inv_pi = [6, 1, 0, 7, 2, 5, 4, 3]
        elif self.words == 16:
            pi = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)
            inv_pi = [0] * 16
            for i in range(16):
                inv_pi[pi[i]] = i

        # Subtract final subkey
        final_subkey = self.subkeys[self.rounds // 4]
        for i in range(self.words):
            words[i] = self._sub_mod_2_64(words[i], final_subkey[i])

        # Process rounds in reverse
        for round_num in range(self.rounds - 1, -1, -1):
            # Inverse permutation
            temp = [0] * self.words
            for i in range(self.words):
                temp[i] = words[inv_pi[i]]
            words = temp

            # Inverse mix function
            round_const_idx = round_num % 8

            if self.words == 4:
                words[0], words[1] = self._inv_mix_function(words[0], words[1],
                                                            self.rotation_constants[round_const_idx][0])
                words[2], words[3] = self._inv_mix_function(words[2], words[3],
                                                            self.rotation_constants[round_const_idx][1])
            else:
                for i in range(0, self.words, 2):
                    pair_idx = i // 2
                    rotation = self.rotation_constants[round_const_idx][pair_idx]
                    words[i], words[i + 1] = self._inv_mix_function(words[i], words[i + 1], rotation)

            # Subtract subkey every 4 rounds
            if round_num % 4 == 0:
                subkey = self.subkeys[round_num // 4]
                for i in range(self.words):
                    words[i] = self._sub_mod_2_64(words[i], subkey[i])

        # Convert back to bytes - output as little-endian to match input format
        return self._words_to_bytes_le(words)


