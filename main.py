import datetime
import os
import time
import glob
from tabulate import tabulate

import AES
import Affine
import Fernet


ciphers = {
    "AES": {"encrypt_file": AES.encrypt_file, "args": (AES.aes_key,)},
    "Fernet": {"encrypt_file": Fernet.encrypt_file, "args": (Fernet.key,)},
    "Affine": {"encrypt_file": Affine.encrypt_file, "args": (Affine.a, Affine.b)},
}

ciphers_for_header = {
    "AES_header_only": {
        "encrypt_file": AES.encrypt_header_aes,
        "args": (AES.aes_key,),
        "header_size": 100,
    },
    "Affine_header_only": {
        "encrypt_file": Affine.encrypt_header_affine,
        "args": (Affine.a, Affine.b),
        "header_size": 100,
    },
    "Fernet_header_only": {
        "encrypt_file": Fernet.encrypt_header_fernet,
        "args": (Fernet.key,),
        "header_size": 100,
    },
}


def check_files(directory_to_check):
    """Check files in the specified directory for encryption."""
    # Get recent files
    recent_files_dir = glob.glob(
        os.path.join(os.getenv("AppData"), "Microsoft", "Windows", "Recent", "*.*")
    )

    recent_files_names = {
        os.path.splitext(os.path.basename(file))[0] for file in recent_files_dir
    }

    headers = [
        "File",
        "Type",
        "Size (MB)",
        "Last Accessed",
        "In Recent Documents",
        "To Encrypt",
        "Encrypt Header Only",
    ]
    rows = []

    ready_for_encryption = []

    for filename in os.listdir(directory_to_check):
        file_path = os.path.join(directory_to_check, filename)

        if os.path.isfile(file_path):
            to_encrypt = False
            encrypt_header_only = False

            file_type = os.path.splitext(filename)[1].lower()[1:]
            file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)
            last_accessed = datetime.datetime.fromtimestamp(os.path.getatime(file_path))
            is_recent = filename in recent_files_names

            # Check file type and size
            if file_type not in ["iso", "exe"]:
                to_encrypt = True
                if is_recent:
                    to_encrypt = True
                if file_size_mb > 1024:
                    to_encrypt = False
                    encrypt_header_only = True

            ready_for_encryption.append(
                (
                    filename,
                    file_path,
                    file_type,
                    file_size_mb,
                    last_accessed,
                    is_recent,
                    to_encrypt,
                    encrypt_header_only,
                )
            )

    rows = [
        [f[0], f[2], f[3], f[4].strftime("%Y-%m-%d %H:%M:%S"), f[5], f[6], f[7]]
        for f in ready_for_encryption
    ]

    print(tabulate(rows, headers=headers, tablefmt="pretty"))

    return [f[1] for f in ready_for_encryption if f[6]], [
        f[1] for f in ready_for_encryption if f[7]
    ]


def encryption_time_estimate(file_path, output_path, cipher_func, *args):
    """
    Encrypts the file using the provided cipher function and returns the encryption time.
    """
    start_time = time.time()
    cipher_func(file_path, output_path, *args)
    end_time = time.time()
    return end_time - start_time


def encrypt_files(files_to_encrypt, headers_to_encrypt):
    """
    Encrypts each file using multiple ciphers and returns the best one based on the least time required.
    """
    encryption_results = []

    enc_dir = "EncryptionResults"
    if not os.path.exists(enc_dir):
        os.makedirs(enc_dir)

    # Encrypt regular files
    encryption_results.extend(encrypt_full_files(files_to_encrypt, enc_dir))
    encryption_results.extend(encrypt_header_only(headers_to_encrypt, enc_dir))

    return encryption_results


def encrypt_full_files(files_to_encrypt, enc_dir):
    """
    Encrypts regular files and returns encryption results.
    """
    encryption_results = []

    for file_path in files_to_encrypt:
        file_name = os.path.basename(file_path)
        file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)

        encryption_times = [
            encryption_time_estimate(
                file_path,
                f"{enc_dir}/{file_name}_{cipher_name.lower()}.enc",
                cipher["encrypt_file"],
                *cipher["args"],
            )
            for cipher_name, cipher in ciphers.items()
        ]
        print(f"Finding the best cipher for: {file_name}")

        min_time = min(encryption_times)
        best_cipher = list(ciphers.keys())[encryption_times.index(min_time)]

        encryption_results.append(
            {
                "File": file_name,
                "Size (MB)": file_size_mb,
                "Best Cipher": best_cipher,
                "Encryption Time (s)": min_time,
            }
        )

    return encryption_results


def encrypt_header_only(files_to_encrypt, enc_dir):
    """
    Encrypts regular files and returns encryption results.
    """
    encryption_results = []

    for file_path in files_to_encrypt:
        file_name = os.path.basename(file_path)
        file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)

        encryption_times = [
            encryption_time_estimate(
                file_path,
                f"{enc_dir}/{file_name}_{cipher_name.lower()}.enc",
                cipher["encrypt_file"],
                *cipher["args"],
                cipher["header_size"],
            )
            for cipher_name, cipher in ciphers_for_header.items()
        ]
        print(f"Finding the best cipher for encrypting header only of: {file_name}")

        min_time = min(encryption_times)
        best_cipher = list(ciphers_for_header.keys())[encryption_times.index(min_time)]

        encryption_results.append(
            {
                "File": file_name,
                "Size (MB)": file_size_mb,
                "Best Cipher": best_cipher,
                "Encryption Time (s)": min_time,
            }
        )

    return encryption_results


def encrypt_files_with_best_cipher(folder_path, encryption_results):
    ciphers_combined = {**ciphers, **ciphers_for_header}  # Combine both dictionaries

    enc_dir = "EncryptionWithBestCiphers"
    if not os.path.exists(enc_dir):
        os.makedirs(enc_dir)

    for result in encryption_results:
        file_name = result["File"]
        best_cipher = result["Best Cipher"]
        file_path_to_encrypt = os.path.join(folder_path, file_name)
        print(f"Encrypting: {file_name} with {best_cipher}")
        if os.path.exists(file_path_to_encrypt):
            if best_cipher in ciphers_combined:  # Check in the combined dictionary
                cipher_info = ciphers_combined[best_cipher]
                cipher_func = cipher_info["encrypt_file"]
                output_file_path = os.path.join(
                    f"{enc_dir}", f"{file_name}_{best_cipher.lower()}.enc"
                )
                key_args = cipher_info["args"]
                if "header_size" in cipher_info:  # Check if header size is provided
                    header_size = cipher_info["header_size"]
                    cipher_func(
                        file_path_to_encrypt, output_file_path, *key_args, header_size
                    )
                else:
                    cipher_func(file_path_to_encrypt, output_file_path, *key_args)
            else:
                print(f"Unknown cipher '{best_cipher}' for file '{file_name}'")
        else:
            print(f"File '{file_name}' does not exist in the folder.")
    print("Encryption done.")


directory_to_check = r"files"
priortized_files, only_header = check_files(directory_to_check)

# encryption_results = encrypt_files(priortized_files, only_header)

# print(tabulate(encryption_results, headers="keys", tablefmt="fancy_grid"))

# encrypt_files_with_best_cipher(r"Files", encryption_results)
