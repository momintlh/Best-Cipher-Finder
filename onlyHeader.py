from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os




def encrypt_header_aes(input_file, output_file, key, header_size):
    """
    Encrypts the header (first header_size bytes) of the input file and saves it back to the original file using AES encryption.
    """
    # Read the first header_size bytes (header)
    with open(input_file, "rb") as file:
        header = file.read(header_size)

    # Encrypt the header using AES encryption
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_header = encryptor.update(header) + encryptor.finalize()

    # Read the remaining content of the input file
    with open(input_file, "rb") as file:
        content = file.read()[header_size:]

    # Write encrypted header and content back to the original file
    with open(output_file, "wb") as file:
        file.write(iv + encrypted_header + content)


import math

a = 123213
m = 256

gcd = math.gcd(a, m)
print("GCD of a and b:", gcd)