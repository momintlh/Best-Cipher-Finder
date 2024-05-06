import shutil
import time
from cryptography.fernet import Fernet
import os

def generate_key(file=False):
    """
    Generates a new encryption key and saves it to a file.
    """
    key = Fernet.generate_key()
   
    if file:
        keys_dir = "Keys"
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)

        key_path = os.path.join(keys_dir, "fernet.key")

        with open(key_path, "wb") as key_file:
            key_file.write(key)

    return key


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

def encrypt_header_fernet(input_file, key, header_size):
    cipher = Fernet(key)
    
    with open(input_file, "r+b") as file:
        header = file.read(header_size)
        
        encrypted_header = cipher.encrypt(header)

        file.seek(0)
        file.write(encrypted_header)
        file.seek(header_size, os.SEEK_SET) 
        shutil.copyfileobj(file, file) 

def embed_decryption_keys(encrypted_file, key, master_key):
    """
    Embeds decryption keys/details at the end of the encrypted file.
    """
  
    int_key = int.from_bytes(key, byteorder="big")
    int_master_key = int.from_bytes(master_key, byteorder="big")
    
    xored_key = int_key ^ int_master_key

    xored_key_bytes = xored_key.to_bytes((xored_key.bit_length() + 7) // 8, byteorder="big")

    with open(encrypted_file, "ab") as file:
        file.write(xored_key_bytes)

def decrypt_file_(input_file, output_file, master_key):
    """
    Decrypts the content of the input file using the embedded decryption key and saves it to the output file.
    """
    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    
    embedded_key_bytes = encrypted_data[-44:]

    embedded_key = int.from_bytes(embedded_key_bytes, byteorder="big")
    int_master_key = int.from_bytes(master_key, byteorder="big")

    cipher = Fernet(key)

    original_key = embedded_key ^ int_master_key
    original_key = original_key.to_bytes((original_key.bit_length() + 7) // 8, byteorder="big")

    decrypted_data = cipher.decrypt(encrypted_data[:-len(original_key)])

    with open(output_file, "wb") as file:
        file.write(decrypted_data)


key = generate_key()
master_key = b"200801087200901089"