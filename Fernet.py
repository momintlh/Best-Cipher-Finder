from cryptography.fernet import Fernet
import os


def generate_key():
    """
    Generates a new encryption key and saves it to a file.
    """
    keys_dir = "Keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    key_path = os.path.join(keys_dir, "fernet.key")

    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)


def load_key():
    """
    Loads the encryption key from the key file.
    """
    with open(r"Keys\fernet.key", "rb") as key_file:
        return key_file.read()


def encrypt_file(input_file, output_file, key):
    """
    Encrypts the content of the input file and saves it to the output file using the provided key.
    """
    cipher = Fernet(key)
    with open(input_file, "rb") as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    with open(output_file, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(input_file, output_file, key):
    """
    Decrypts the content of the input file and saves it to the output file using the provided key.
    """
    cipher = Fernet(key)
    with open(input_file, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_file, "wb") as file:
        file.write(decrypted_data)


def encrypt_header_fernet(input_file, output_file, key, header_size):
    cipher = Fernet(key)
    with open(input_file, "rb") as file:
        header = file.read(header_size)

    encrypted_header = cipher.encrypt(header)

    with open(input_file, "rb") as file:
        content = file.read()

    # Combine encrypted header and content
    encrypted_content = encrypted_header + content[header_size:]
    with open(output_file, "wb") as file:
        file.write(encrypted_content)


generate_key()
key = load_key()