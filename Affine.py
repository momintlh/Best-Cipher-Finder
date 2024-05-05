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

def encrypt_data_affine(data, key_a, key_b):
    """
    Encrypts binary data using the Affine cipher with the provided keys.
    """
    encrypted_data = bytearray()
    for batch in chunk_data(data, 1024): 
        encrypted_batch = []
        for byte in batch:
            encrypted_byte = (byte * key_a + key_b) % 256
            encrypted_batch.append(encrypted_byte)
        encrypted_data.extend(encrypted_batch)
    return bytes(encrypted_data)

def decrypt_data_affine(data, key_a, key_b):
    """
    Decrypts binary data using the Affine cipher with the provided keys.
    """
    decrypted_data = bytearray()
    inv_a = mod_inverse(key_a, 256) 

    for batch in chunk_data(data, 1024):  
        decrypted_batch = []
        for byte in batch:
            decrypted_byte = (inv_a * (byte - key_b)) % 256
            decrypted_batch.append(decrypted_byte)
        decrypted_data.extend(decrypted_batch)

    return bytes(decrypted_data)

# utils
def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of 'a' modulo 'm'.
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def chunk_data(data, chunk_size):
    """
    Splits the data into smaller chunks of a specified size.
    """
    return (data[i : i + chunk_size] for i in range(0, len(data), chunk_size))

def write_key_to_file(key_a, key_b, filename):
    with open(filename, "w") as file:
        file.write(f"{key_a}\n")
        file.write(f"{key_b}")

def read_key_from_file(filename):
    with open(filename, "r") as file:
        key_a = int(file.readline())
        key_b = int(file.readline())
        return key_a, key_b

def embed_decryption_keys(encrypted_file, key_a, key_b, master_key):
    """
    Embeds decryption keys/details at the end of the encrypted file.
    """
    int_key_a = int(key_a)
    int_key_b = int(key_b)
    int_master_key = int.from_bytes(master_key, byteorder="big")

    xored_key_a = int_key_a ^ int_master_key
    xored_key_b = int_key_b ^ int_master_key

    xored_key_a = xored_key_a.to_bytes((xored_key_a.bit_length() + 7) // 8, byteorder="big")
    xored_key_b = xored_key_b.to_bytes((xored_key_b.bit_length() + 7) // 8, byteorder="big")

    with open(encrypted_file, "ab") as file:
        file.write(xored_key_a)
        file.write(xored_key_a)

a = 123213
b = 3241323

write_key_to_file(a, b, r"Keys\affine.key")
key_a_loaded, key_b_loaded = read_key_from_file(r"Keys\affine.key")

master_key = b"200801087200901089"