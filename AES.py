from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

iv = os.urandom(16)  # Generate a random IV (Initialization Vector), 


def generate_aes_key(password, salt, key_length=32):
    """
    Generates an AES key using a password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed for your use case
        backend=default_backend(),
    )
    return kdf.derive(password)


def encrypt_file(input_file, output_file, key):
    """
    Encrypts the content of the input file and saves it to the output file using AES encryption with the provided key.
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    encryptor = cipher.encryptor()
    with open(input_file, "rb") as file:
        data = file.read()

    # Pad the data to be a multiple of 16 bytes (block size)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, "wb") as file:
        file.write(iv)  
        file.write(encrypted_data)


def decrypt_file_aes(input_file, output_file, key):
    """
    Decrypts the content of the input file and saves it to the output file using AES decryption with the provided key.
    """
    backend = default_backend()
    with open(input_file, "rb") as file:
        iv = file.read(16)  # Read the IV from the file
        encrypted_data = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(output_file, "wb") as file:
        file.write(unpadded_data)


def save_key_hex(key):
    keys_dir = "Keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    key_path = os.path.join(keys_dir, "AES.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)


def load_aes_key():
    with open(r"Keys\AES.key", "rb") as key_file:
        return key_file.read()


def encrypt_header_aes(input_file, output_file, key, header_size):
    """
    Encrypts the header (first header_size bytes) of the input file and saves it back to the original file using AES encryption.
    """

    with open(input_file, "rb") as file:
        header = file.read(header_size)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_header = encryptor.update(header) + encryptor.finalize()

    with open(input_file, "rb") as file:
        content = file.read()[header_size:]

    with open(output_file, "wb") as file:
        file.write(iv + encrypted_header + content)


password = b"MyStrongPassword123"
salt = b"SomeSalt"
aes_key = generate_aes_key(password, salt)


save_key_hex(aes_key)
loaded_aes_key = load_aes_key()