import os
import sqlite3
import struct
import Answers

from Encoding import generate_aes_key, rsa_encryption
import InitDb

SIZE_NAME = 255

def get_req(req_details):
    # Unpack the request details
    (name, ), data = struct.unpack('<255s', req_details[:SIZE_NAME]), req_details[SIZE_NAME:]
    return [name, data]

def create_encrypt_AES(client_id, user_name, public_key):
    # Generate AES key
    aes_key = generate_aes_key()

    # Encrypt the AES key with the public key
    encrypted_aes = rsa_encryption(public_key, aes_key)
    encrypted_aes_size = len(encrypted_aes)
    # Add the public key and encrypted AES to the clients table
    return InitDb.add_public_key_AES(client_id, user_name, public_key, encrypted_aes, aes_key, encrypted_aes_size)


def get_curser_serverDB():
    conn = sqlite3.connect(r"server.db")
    mycursor = conn.cursor()
    return mycursor, conn


def save_file_in_server(file_name, decrypt_file):
    decoded_file, encoding = decode_decrypted_file(decrypt_file)
    if decoded_file == 0:
        return Answers.send_reg_failed()

    with open(file_name, "w", encoding=encoding) as file:
        file.write(decoded_file)

    return os.path.dirname(__file__)

def decode_decrypted_file(decrypt_file):
    encodings = ["utf-8", "utf-16", "ISO-8859-1", "windows-1252", "latin-1"]
    for encoding in encodings:
        try:
            return decrypt_file.decode(encoding), encoding
        except UnicodeDecodeError:
            pass
    return 0, 0

