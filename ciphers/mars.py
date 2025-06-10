# === MARS Cipher in Python ===
from katcrypt.constants.mars_tables import sbox, word_table


class MARS:
    # ==================================
    # Constructor
    # ==================================

    def __init__(self, key: bytes):
        self.key = key
        self.key_length = len(key)
        self.block_size = 16

        if not (16 <= self.key_length <= 56) or self.key_length % 4 != 0:
            raise ValueError("Key must be 16-56 bytes and word-aligned (multiple of 4 bytes)")

        self.round_keys = [0] * 40
        self._expand_key()

    # ==================================
    # Helper Functions
    # ==================================

    def _sum(self, val1, val2):
        return (val1 + val2) & 0xFFFFFFFF

    def _sub(self, val1, val2):
        return (val1 - val2) & 0xFFFFFFFF

    def _mul(self, val1, val2):
        return (val1 * val2) & 0xFFFFFFFF

    def _rotl(self, x: int, n: int, bits: int = 32) -> int:
        n = n % bits
        return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)

    def _rotr(self, x: int, n: int, bits: int = 32) -> int:
        n = n % bits
        return ((x >> n) | (x << (bits - n))) & ((1 << bits) - 1)

    def _bytes_to_words(self, block: bytes):
        return [int.from_bytes(block[i:i + 4], 'little') for i in range(0, 16, 4)]

    def _words_to_bytes(self, words):
        return b''.join(w.to_bytes(4, 'little') for w in words)

    def _build_mask(self, w):
        """
        Build a 32-bit mask where M_i = 1 if w_i belongs to a sequence of ten
        consecutive 0's or 1's in w and also 2 ≤ i ≤ 30 and w_{i-1} = w_i = w_{i+1}
        """
        mask = 0
        for bit in range(2, 31):
            belongs_to_sequence = False

            for start in range(max(0, bit - 9), min(bit + 1, 23)):
                window = (w >> start) & 0x3FF
                if window == 0x000 or window == 0x3FF:
                    belongs_to_sequence = True
                    break

            if belongs_to_sequence:
                # Check if w_{i-1} = w_i = w_{i+1}
                triple = (w >> (bit - 1)) & 0x7
                if triple == 0b000 or triple == 0b111:
                    mask |= (1 << bit)

        return mask

    # ==================================
    # Key Schedule
    # ==================================

    def _expand_key(self):
        """Expands the input key into 40 words K[0..39]."""
        number_of_key_words = self.key_length // 4
        temporary_key_words = [0] * 15

        for i in range(number_of_key_words):
            temporary_key_words[i] = int.from_bytes(self.key[i * 4:(i + 1) * 4], 'little')

        temporary_key_words[number_of_key_words] = number_of_key_words

        for j in range(4):
            for i in range(15):
                temporary_key_words[i] = temporary_key_words[i] ^ self._rotl(temporary_key_words[(i - 7) % 15] ^ temporary_key_words[(i - 2) % 15],3) ^ ((4 * i) + j)

            for stirring_round in range(4):
                for i in range(15):
                    temporary_key_words[i] = self._rotl((self._sum(temporary_key_words[i], sbox[temporary_key_words[(i - 1) % 15] & 0x1FF])), 9)

            for i in range(10):
                self.round_keys[(10 * j) + i] = temporary_key_words[(4 * i) % 15]

        for i in range(5, 36, 2):
            j = self.round_keys[i] & 0x3
            w = self.round_keys[i] | 0x3

            M = self._build_mask(w)
            r = (self.round_keys[i - 1]) & 0x1F
            p = self._rotl(word_table[j], r)

            self.round_keys[i] = w ^ (p & M)

    # ==================================
    # E-Function
    # ==================================

    def _e_function(self, data_word, key_word1, key_word2):
        middle = self._sum(data_word, key_word1)
        right = self._mul(self._rotl(data_word, 13), key_word2)
        i = middle & 0x1FF # Lowest 9 bits of middle
        left = sbox[i]
        right = self._rotl(right, 5)
        r = right & 0x1F
        middle = self._rotl(middle, r)
        left = left ^ right
        right = self._rotl(right, 5)
        left = left ^ right
        r = right & 0x1F
        left = self._rotl(left, r)

        return left, middle, right

    # ==================================
    # Mixing
    # ==================================

    def forward_mix(self, data_word):
        sbox0 = sbox[0:256]  # First 256 entries
        sbox1 = sbox[256:512]  # Last 256 entries
        for i in range(4):
            data_word[i] = self._sum(data_word[i], self.round_keys[i])
        for i in range(8):
            data_word[1] = data_word[1] ^ sbox0[data_word[0] & 0xFF]
            data_word[1] = self._sum(data_word[1], sbox1[(data_word[0] >> 8) & 0xFF])
            data_word[2] = self._sum(data_word[2], sbox0[(data_word[0] >> 16) & 0xFF])
            data_word[3] = data_word[3] ^ sbox1[(data_word[0] >> 24) & 0xFF]

            data_word[0] = self._rotr(data_word[0], 24)

            if i == 0 or i == 4:
                data_word[0] = self._sum(data_word[0], data_word[3])
            if i == 1 or i == 5:
                data_word[0] = self._sum(data_word[0], data_word[1])

            data_word[:] = [data_word[1], data_word[2], data_word[3], data_word[0]]

        return data_word

    def backward_mix(self, data_word):
        sbox0 = sbox[0:256]  # First 256 entries
        sbox1 = sbox[256:512]  # Last 256 entries

        for i in range(8):
            if i == 2 or i == 6:
                data_word[0] = self._sub(data_word[0], data_word[3])
            if i == 3 or i == 7:
                data_word[0] = self._sub(data_word[0], data_word[1])

            data_word[1] = data_word[1] ^ sbox1[data_word[0] & 0xFF]
            data_word[2] = self._sub(data_word[2], sbox0[(data_word[0] >> 24) & 0xFF])
            data_word[3] = self._sub(data_word[3], sbox1[(data_word[0] >> 16) & 0xFF])
            data_word[3] = data_word[3] ^ sbox0[(data_word[0] >> 8) & 0xFF]

            data_word[0] = self._rotl(data_word[0], 24)

            data_word[:] = [data_word[1], data_word[2], data_word[3], data_word[0]]

        for i in range(4):
            data_word[i] = self._sub(data_word[i], self.round_keys[36 + i])

        return data_word

    def inverse_backward_mix(self, data_word):
        sbox0 = sbox[0:256]  # First 256 entries
        sbox1 = sbox[256:512]  # Last 256 entries
        for i in range(4): # for i = 0 to 3 do
            data_word[i] = self._sum(data_word[i], self.round_keys[36 + i]) #D[i]=D[i]+K[36+i]
        for i in range(7, -1, -1): # for i = 7 down to 0 do
            data_word[:] = [data_word[3], data_word[0], data_word[1], data_word[2]] # (D[3];D[2];D[1];D[0]) <-(D[2];D[1];D[0];D[3])

            data_word[0] = self._rotr(data_word[0], 24)

            data_word[3] = data_word[3] ^ sbox0[(data_word[0] >> 8) & 0xFF]
            data_word[3] = self._sum(data_word[3], sbox1[(data_word[0] >> 16) & 0xFF])
            data_word[2] = self._sum(data_word[2], sbox0[(data_word[0] >> 24) & 0xFF])
            data_word[1] = data_word[1] ^ sbox1[data_word[0] & 0xFF]

            if i == 2 or i == 6:
                data_word[0] = self._sum(data_word[0], data_word[3])
            if i == 3 or i == 7:
                data_word[0] = self._sum(data_word[0], data_word[1])

        return data_word

    def inverse_forward_mix(self, data_word):
        sbox0 = sbox[0:256]  # First 256 entries
        sbox1 = sbox[256:512]  # Last 256 entries

        for i in range(7, -1, -1):
            data_word[:] = [data_word[3], data_word[0], data_word[1], data_word[2]]
            if i == 0 or i == 4:
                data_word[0] = self._sub(data_word[0], data_word[3])
            if i == 1 or i == 5:
                data_word[0] = self._sub(data_word[0], data_word[1])

            data_word[0] = self._rotl(data_word[0], 24)

            data_word[3] = data_word[3] ^ sbox1[(data_word[0] >> 24) & 0xFF]
            data_word[2] = self._sub(data_word[2], sbox0[(data_word[0] >> 16) & 0xFF])
            data_word[1] = self._sub(data_word[1], sbox1[(data_word[0] >> 8) & 0xFF])
            data_word[1] = data_word[1] ^ sbox0[data_word[0] & 0xFF]

        for i in range(4):
            data_word[i] = self._sub(data_word[i], self.round_keys[i])

        return data_word

    # ==================================
    # Keyed Transformation Phase
    # ==================================

    def _keyed_transform(self, data_words, round_keys):
        for i in range(16):
            out1, out2, out3 = self._e_function(data_words[0], round_keys[i * 2 + 4], round_keys[i * 2 + 5])
            data_words[0] = self._rotl(data_words[0], 13)
            data_words[2] = self._sum(data_words[2], out2)

            if i < 8:
                data_words[1] = self._sum(data_words[1], out1)
                data_words[3] ^= out3
            else:
                data_words[3] = self._sum(data_words[3], out1)
                data_words[1] ^= out3

            data_words[:] = [data_words[1], data_words[2], data_words[3], data_words[0]]

    def _inverse_keyed_transform(self, data_words, round_keys):
        for i in range(15, -1, -1):
            data_words[:] = [data_words[3], data_words[0], data_words[1], data_words[2]]

            data_words[0] = self._rotr(data_words[0], 13)

            out1, out2, out3 = self._e_function(data_words[0], round_keys[i * 2 + 4], round_keys[i * 2 + 5])

            data_words[2] = self._sub(data_words[2], out2)

            if i < 8:
                data_words[1] = self._sub(data_words[1], out1)
                data_words[3] ^= out3
            else:
                data_words[3] = self._sub(data_words[3], out1)
                data_words[1] ^= out3

    # ==================================
    # Encryption / Decryption of Block
    # ==================================

    def encrypt_block(self, block: bytes) -> bytes:
        data = self._bytes_to_words(block)  # Convert to 4 words

        # Phase 1: Forward mixing
        self.forward_mix(data)

        # Phase 2: Keyed transformation
        self._keyed_transform(data, self.round_keys)

        # Phase 3: Backward mixing
        self.backward_mix(data)

        return self._words_to_bytes(data)

    def decrypt_block(self, block: bytes) -> bytes:
        data = self._bytes_to_words(block)

        # Phase 3 inverse: Undo backward mixing
        self.inverse_backward_mix(data)

        # Phase 2 inverse: Undo keyed transformation
        self._inverse_keyed_transform(data, self.round_keys)

        # Phase 1 inverse: Undo forward mixing
        self.inverse_forward_mix(data)

        return self._words_to_bytes(data)

