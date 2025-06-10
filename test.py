from katcrypt.ciphers.threefish import Threefish
from katcrypt.modes.gcm import GCM
from katcrypt import encrypt, decrypt
from katcrypt.utils import generate_key, generate_iv

plaintext = b"Hello World!"
key = generate_key(1024)
iv = generate_iv(16)
aad = b"AAD"

# Api option 1
ciphertext, tag = encrypt(cipher="threefish", mode="gcm", key=key, plaintext=plaintext, iv=iv, aad=aad)
print(f"Ciphertext: {ciphertext}")

decrypted = decrypt(cipher="threefish", mode="gcm", key=key, ciphertext=ciphertext, iv=iv, aad=aad, auth_tag=tag)
print(f"Decrypted: {decrypted}\n")


# Api option 2
mars_gcm = GCM(Threefish(key=key))

ciphertext, tag = mars_gcm.encrypt(plaintext=plaintext, iv=iv, aad=aad)
print(f"Ciphertext: {ciphertext}")

decrypted = mars_gcm.decrypt(ciphertext=ciphertext, iv=iv, aad=aad, auth_tag=tag)
print(f"Decrypted: {decrypted}")
