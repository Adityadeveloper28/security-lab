from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import os

class AES:
    def __init__(self):
        self.KEY_SIZE = 32  # 256 bits for AES
        self.IV_SIZE = 16   # 128 bits for AES
        self.backend = default_backend()

    def generate_key(self):
        return os.urandom(self.KEY_SIZE)  # Generating a random key

    def encrypt(self, key, data):
        iv = os.urandom(self.IV_SIZE)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def decrypt(self, key, data):
        iv = data[:self.IV_SIZE]
        ciphertext = data[self.IV_SIZE:-16]  # Remove 16 bytes for the tag
        tag = data[-16:]  # Last 16 bytes are the tag

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

if __name__ == "__main__":
    aes = AES()
    key = aes.generate_key()

    message = b"Hello, welcome to the encryption world"
    encrypted_data = aes.encrypt(key, message)
    decrypted_data = aes.decrypt(key, encrypted_data)

    print("Original Message:", message)
    print("Encrypted Data:", base64.b64encode(encrypted_data).decode("utf-8"))
    print("Decrypted Data:", decrypted_data.decode("utf-8"))
