import os


def encrypt_file(input_file, output_file, key_a, key_b):
    """
    Encrypts the content of the input file and saves it to the output file using the Affine cipher with the provided keys.
    """
    with open(input_file, "rb") as file:
        data = file.read()

    encrypted_data = encrypt_data_affine(data, key_a, key_b)

    with open(output_file, "wb") as file:
        file.write(encrypted_data)


def encrypt_header_affine(input_file, output_file, key_a, key_b, header_size):
    """
    Encrypts the content of the input file and saves it to the output file using the Affine cipher with the provided keys.
    """
    with open(input_file, "rb") as file:
        data = file.read(header_size)

    encrypted_data = encrypt_data_affine(data, key_a, key_b)

    with open(input_file, "rb") as file:
        content = file.read()

    encrypted_content = encrypted_data + content[header_size:]
    with open(output_file, "wb") as file:
        file.write(encrypted_content)


def decrypt_file_affine(input_file, output_file, key_a, key_b):
    """
    Decrypts the content of the input file and saves it to the output file using the Affine cipher with the provided keys.
    """
    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decrypt_data_affine(encrypted_data, key_a, key_b)

    with open(output_file, "wb") as file:
        file.write(decrypted_data)


# Helper functions for Affine Cipher encryption and decryption
def encrypt_data_affine(data, key_a, key_b):
    """
    Encrypts binary data using the Affine cipher with the provided keys.
    """
    encrypted_data = bytearray()
    for byte in data:
        encrypted_byte = (byte * key_a + key_b) % 256
        encrypted_data.append(encrypted_byte)
    return bytes(encrypted_data)


def decrypt_data_affine(data, key_a, key_b):
    """
    Decrypts binary data using the Affine cipher with the provided keys.
    """
    decrypted_data = bytearray()
    for byte in data:
        decrypted_byte = (mod_inverse(key_a, 256) * (byte - key_b)) % 256
        decrypted_data.append(decrypted_byte)
    return bytes(decrypted_data)


def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of 'a' modulo 'm'.
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# key write and read functions:
def write_key_to_file(key_a, key_b, filename):
    with open(filename, "w") as file:
        file.write(f"{key_a}\n")
        file.write(f"{key_b}")


def read_key_from_file(filename):
    with open(filename, "r") as file:
        key_a = int(file.readline())
        key_b = int(file.readline())
        return key_a, key_b


a = 123213
b = 3241323

write_key_to_file(a, b, r"Keys\affine.key")
key_a_loaded, key_b_loaded = read_key_from_file(r"Keys\affine.key")
