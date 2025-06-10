# === AES Cipher in Python ===
from katcrypt.constants.aes_tables import sbox, inverse_sbox, round_constants

class AES:
    def __init__(self, key: bytes):
        self.key = key
        self.key_length = len(key)
        self.block_size = 16

        if self.key_length == 16:
            self.words_in_key = 4
            self.rounds = 10
        elif self.key_length == 24:
            self.words_in_key = 6
            self.rounds = 12
        elif self.key_length == 32:
            self.words_in_key = 8
            self.rounds = 14
        else:
            raise ValueError("Key must be 16, 24, or 32 bytes long.")

        self.word_bytes = 4
        self.round_keys = []
        self._expand_key()


    #####################################
    # Helper Functions
    #####################################
    def _rot_word(self, word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    def _sub_word(self, word: list[int]) -> list[int]:
        return [sbox[byte] for byte in word]

    def _block_to_state(self, block: bytes) -> list[list[int]]:
        state = [[0] * 4 for _ in range(4)]
        for index in range(16):
            row, col = index % 4, index // 4
            state[row][col] = block[index]
        return state

    def _state_to_block(self, state: list[list[int]]) -> bytes:
        output = bytearray()
        for col in range(4):
            for row in range(4):
                output.append(state[row][col])
        return bytes(output)

    def _gmul(self, factor_a: int, factor_b: int) -> int:
        result = 0
        for _ in range(8):
            if factor_b & 1:
                result ^= factor_a

            high_bit_set = factor_a & 0x80
            factor_a <<= 1

            if high_bit_set:
                factor_a ^= 0x11b

            factor_b >>= 1
        return result


    #####################################
    # Key Expansion
    #####################################
    def _expand_key(self):
        key_schedule: list[list[int]] = []
        for offset in range(0, self.key_length, self.word_bytes):
            word = list(self.key[offset: offset + self.word_bytes])
            key_schedule.append(word)

        total_words = 4 * (self.rounds + 1)

        for word_index in range(self.words_in_key, total_words):
            prev_word = key_schedule[word_index - 1]

            if self.key_length == 32 and word_index % self.words_in_key == 4:
                temp_word = self._sub_word(prev_word)
            elif word_index % self.words_in_key == 0:
                rotated_word = self._rot_word(prev_word)
                substituted_word = self._sub_word(rotated_word)
                substituted_word[0] ^= round_constants[word_index // self.words_in_key - 1]
                temp_word = substituted_word
            else:
                temp_word = prev_word

            prior_word = key_schedule[word_index - self.words_in_key]
            new_word = [temp_byte ^ prior_byte for temp_byte, prior_byte in zip(temp_word, prior_word)]
            key_schedule.append(new_word)

        for round_index in range(0, len(key_schedule), 4):
            flat_key = (key_schedule[round_index] +
                        key_schedule[round_index + 1] +
                        key_schedule[round_index + 2] +
                        key_schedule[round_index + 3])
            round_matrix = self._block_to_state(flat_key)
            self.round_keys.append(round_matrix)


    #####################################
    # Forward Transformations
    #####################################
    def _sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        for row in range(4):
            for col in range(4):
                state[row][col] = sbox[state[row][col]]
        return state

    def _shift_rows(self, state: list[list[int]]) -> list[list[int]]:
        for row in range(4):
            state[row] = state[row][row:] + state[row][:row]
        return state

    def _mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        for col in range(4):
            state0, state1, state2, state3 = (state[row][col] for row in range(4))

            state[0][col] = self._gmul(2, state0) ^ self._gmul(3, state1) ^ state2 ^ state3
            state[1][col] = state0 ^ self._gmul(2, state1) ^ self._gmul(3, state2) ^ state3
            state[2][col] = state0 ^ state1 ^ self._gmul(2, state2) ^ self._gmul(3, state3)
            state[3][col] = self._gmul(3, state0) ^ state1 ^ state2 ^ self._gmul(2, state3)
        return state


    #####################################
    # Inverse Transformations
    #####################################
    def _inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        for row in range(4):
            for col in range(4):
                state[row][col] = inverse_sbox[state[row][col]]
        return state

    def _inv_shift_rows(self, state: list[list[int]]) -> list[list[int]]:
        for row in range(4):
            state[row] = state[row][-row:] + state[row][:-row]
        return state

    def _inv_mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        for col in range(4):
            state0, state1, state2, state3 = (state[row][col] for row in range(4))

            state[0][col] = self._gmul(14, state0) ^ self._gmul(11, state1) ^ self._gmul(13, state2) ^ self._gmul(9,state3)
            state[1][col] = self._gmul(9, state0) ^ self._gmul(14, state1) ^ self._gmul(11, state2) ^ self._gmul(13,state3)
            state[2][col] = self._gmul(13, state0) ^ self._gmul(9, state1) ^ self._gmul(14, state2) ^ self._gmul(11,state3)
            state[3][col] = self._gmul(11, state0) ^ self._gmul(13, state1) ^ self._gmul(9, state2) ^ self._gmul(14,state3)

        return state


    #####################################
    # Round Key Addition
    #####################################
    def _add_round_key(self, state: list[list[int]], round_key: list[list[int]]) -> None:
        for row in range(4):
            for col in range(4):
                state[row][col] ^= round_key[row][col]


    #####################################
    # Block Cipher Interface
    #####################################
    def encrypt_block(self, block: bytes) -> bytes:
        state = self._block_to_state(block)

        self._add_round_key(state, self.round_keys[0])

        for round_idx in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round_idx])

        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.rounds])

        return self._state_to_block(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = self._block_to_state(block)

        self._add_round_key(state, self.round_keys[self.rounds])

        for round_idx in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)

            state = self._inv_sub_bytes(state)

            self._add_round_key(state, self.round_keys[round_idx])

            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0])

        return self._state_to_block(state)
